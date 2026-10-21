"""What expires in the next N days.

The threshold ladder is taken literally from NSHC (NshcCertTruth.ps1) so that
the same certificate gets the same classification in both products. With the
thresholds in two places, the same certificate could yield two conclusions -
which is exactly why NSHC once reduced them to a single source.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap, export_age
from nsmcp.cert_usage import absent_dimensions, other_usage
from nsmcp.export import (
    KEY_MISSING_TEXT,
    field_gap as _field_gap,
    identity_shape_clause as _identity_shape_clause,
    shape_of,
)
from nsmcp.knowledge import Knowledge
from nsmcp.ssl_precedence import field_text, field_token

THRESHOLDS = {"critical": 14, "warning": 30, "notice": 60, "horizon": 90}
RESOURCE = "config/sslcertkey"
VSERVER_BINDING = "sslvserver_sslcertkey_binding.by-parent.json"
CERT_BINDING = "sslcertkey_binding.by-parent.json"

# The nested kinds of CERT_BINDING this version reads, in the aggregate shape
# the real collector writes (measured on both lab fixtures): a certificate
# bound to an ssl-vserver (`servername`) and to a service (`servicename`).
# Every other nested `*_binding` kind on a certificate is one this version has
# no rule for - that certificate is then not provably unused (see
# `_usage_and_gaps`).
CERT_CHILDREN = ("sslcertkey_sslvserver_binding", "sslcertkey_service_binding")

# The shape of a binding-kind key that may be repeated in a reason: a
# lower-case NITRO resource name. Anything else is named by its shape only.
_BINDING_KIND = re.compile(r"[a-z][a-z0-9_]{0,78}_binding")

# The four usage states, in the order they are SORTED. This order is the
# whole point of A8: an expiry list on days puts a certificate nobody uses
# above one that takes a service down tomorrow.
#
# OPEN POINT AT OPLEVERING: the two
# NSHC mirror files this design is ported from
# (backend/deep/NshcCertUsageTruth.ps1, backend/deep/New-NshcCertRadar.ps1,
# introduced in NSHC 1.1.0 after a measured defect - issue #4) are NOT in the
# released NSHC 1.0.1 tree. The parity test therefore does not,
# and cannot, cover these four states - there is nothing released to compare
# against. Recorded here as an open point at delivery.
USAGE_WORDS = ("gebonden", "uitgever", "los", "onbekend")

_STATE_ORDER = {state: index for index, state in enumerate(USAGE_WORDS)}

NOT_ASSESSED_USAGE = NotAssessed(
    subject="gebruik buiten de appliance",
    reason=(
        "of hetzelfde certificaat ook op een backend-server staat is vanaf de appliance"
        " niet te zien; dat is geen 'los', dat is niet vastgesteld"
    ),
)


@dataclass(frozen=True)
class Usage:
    certkey: str
    state: str
    used_by: tuple[str, ...] = ()
    reason: str = ""
    # The uses outside the bindings with virtual servers (`cert_usage`), as
    # the expiry list names them: kind, object and role, in reading order.
    # Apart from `used_by` because they are not vservers: a caller that reads
    # `used_by` as "the virtual servers to rebind" keeps reading exactly that.
    used_elsewhere: tuple[str, ...] = ()


# `_field_gap` and `_identity_shape_clause` used to be defined here. An
# earlier review found chain.py had
# copied both byte-for-byte rather than importing them - a fresh second copy
# of Dutch phrasing already corrected twice under review. Both are now
# `nsmcp.export.field_gap` / `nsmcp.export.identity_shape_clause`, imported
# above under their original local names so every call site below (and the
# review history recorded in their docstrings there) is unchanged.


def _cert_binding_target(row: dict) -> str:
    """The name a cert-side binding row points AT, whichever field this
    binding TYPE happens to carry it under - the aggregate structure of the
    real export shows two different field names for this depending on
    whether the row is a service binding (`servicename`) or a vserver
    binding (`servername`); `vservername` is included for the same field
    NITRO uses on the OTHER binding file.

    Returns "" both when the row carries NONE of these three fields and
    when one of them IS present but not readable text - `field_text`
    collapses "absent" and "present but unreadable" the same way, and this
    function does not itself tell them apart. A row with none of the three
    is an honest zero-binding row, no longer "referenced" (the caller's
    `if target:` no longer counts it). A row with one of the three
    present-but-unreadable is a DIFFERENT fact - it proves the certificate
    IS referenced, only the target's name is unreadable - so the caller
    (`_usage_and_gaps`) draws that distinction itself, with its own
    `_field_gap` calls on the same three fields, rather than this function
    trying to return two different kinds of "".

    The caller does not surface this return value in `used_by` - it stays a
    membership signal only (a certkey with an entry in `cert_bound` is
    `gebonden`), never a rendered name. `servicename`/`servername` are a
    source/field combination `disclosure.names_from_export()` does not
    collect, so a name from here would reach 'beperkt'/'minimaal' unmasked.
    """
    return field_text(row, "servicename") or field_text(row, "servername") or field_text(row, "vservername")


# `signaturealg` must not reach `key_bits` UNGATED - `field_text()`
# guarantees only "a stripped string", never "short and single-line". A
# real value is a short run of letters, digits and hyphens with NO
# whitespace at all (measured on the real fixture:
# "sha256WithRSAEncryption"; on the ECC fixture, tests/test_tls_baseline.py:
# "ecdsa-with-SHA256") - `repeatable_token` (answer.py) does not fit here,
# its char class is uppercase-only by design for a NITRO enum, and would
# reject "sha256WithRSAEncryption" outright. This is the bespoke shape gate
# for this one field, the same TREATMENT `publickeysize` already gets one
# line above (`.isdigit()`): a value outside the shape is `export.shape_of`,
# never echoed.
_SIGNATURE_ALG_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}")


def _signature_text(row: dict, field: str = "signaturealg") -> str:
    """The signaturealg text for evidence, or a name for what went wrong.

    Mirrors `_field_gap`'s case-insensitive key scan so the ORIGINAL raw
    value (not the "" that `field_text` would collapse it to) reaches
    `shape_of` when the value is not usable text at all - a bool/int/
    list/dict/null each names its own type, never a generic default.

    `shape_of` is built for a value `field_text` would fail on (not a
    string, or a blank/whitespace-only one) and always names THAT case
    "een lege of alleen-witruimte tekstwaarde" - true for a blank string,
    false for 55 characters of real text that simply has the wrong shape.
    A non-blank string that fails the gate gets its own wording instead,
    the same split
    `coverage.py` already draws (`_resource_key`): `shape_of` for a value
    that is not usable text at all, "zonder de vorm van ..." for text
    that IS usable but has the wrong shape.
    """
    lowered = field.lower()
    for key, raw in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            if isinstance(raw, str):
                text = raw.strip()
                if text:
                    if _SIGNATURE_ALG_PATTERN.fullmatch(text):
                        return text
                    return "zonder de vorm van een algoritmenaam"
            return shape_of(raw)
    return KEY_MISSING_TEXT


def binding_kind_names(kinds: tuple[str, ...]) -> str:
    """The binding kinds for a reason: each one repeated only when it has the
    shape of a NITRO resource name (it comes out of the export's content),
    otherwise named by that fact alone. Shared with impact.py, which names
    the same unread kinds for the questioned certificate, and with chain.py,
    which names the kinds a contentswitching-vserver routes through."""
    named = [
        kind if _BINDING_KIND.fullmatch(kind) else "een bindingssoort zonder de vorm van een resourcenaam"
        for kind in kinds
    ]
    return ", ".join(dict.fromkeys(named))


def _usage_and_gaps(export) -> tuple[tuple[Usage, ...], tuple[ReadGap, ...]]:
    """Usage state per certificate, and the read gaps the sources behind it
    produced getting there - derived ONCE, so `usage_per_certificate()` and
    `what_expires()` do not read the same files twice with two chances for
    the gap lists to drift.

    Four states, and the difference between the last two is the reason this
    exists (issue #4, the NSHC 1.1.0 regression): "los" is a CLAIM that
    nobody uses this certificate, and that claim needs every source that
    could refute it to be BOTH read AND actually consulted - not merely
    read without error. Four things can break that claim, and each
    degrades every not-yet-classified certificate to `onbekend` rather than
    the favourable `los`, because none of them can be pinned to a single
    certificate the way a well-formed row can:

    - `VSERVER_BINDING` (`sslvserver_sslcertkey_binding.by-parent.json`)
      cannot be parsed at all, or a row inside it carries a
      present-but-unreadable `certkeyname`/`vservername` - the unreadable
      row could have named ANY certificate as bound.
    - `CERT_BINDING` (`sslcertkey_binding.by-parent.json`) cannot be parsed
      at all, or a row inside it carries a present-but-unreadable
      `certkey` - same reasoning. On the real export this file carries the
      'aggregate' shape (measured 2026-09-06); it is read per child kind
      (`CERT_CHILDREN`), and the list shape is read as well. A certificate
      whose own document carries a kind outside `CERT_CHILDREN` is
      `onbekend` on its own - not every certificate. A row WITH a
      readable `certkey` but a present-but-unreadable `servicename`/
      `servername`/`vservername` gaps the same way: that row PROVES the
      certificate is referenced, so treating its unreadable target as the
      honest zero-binding row is the dangerous direction, not the safe one.
    - A certificate's OWN `certkey` is genuinely absent, with no `name` to
      fall back on either, OR `certkey` is present but unreadable
      regardless of whether a readable `name` also identifies the row - the
      row still classifies under that `name`, but an unreadable `certkey`
      next to it is not excused: a certificate archived only under its
      `name` is invisible to `bound`/`cert_bound`, which key on
      `certkeyname`/`certkey`, never `name` - OR its `linkcertkeyname` is
      present but unreadable - the well-formed rows still tell us who
      issues whom, but a row whose own identity is missing or unreadable,
      or whose issuer is unreadable, means an issuer relationship COULD
      exist that this pass cannot see, so no certificate elsewhere in this
      export can be cleared as `los` on the strength of this source either;
      the identity half of this is gated the same way as the rest.
    - The use outside the bindings (`cert_usage`: SAML actions, SAML IdP
      profiles, SSL servicegroups) is not read in full: one of its three
      sources is not in the export, not usably read, or carries a
      reference that cannot be read. A certificate those sources DO name is
      `gebonden` regardless.
    """
    certs, gap = export.objects(RESOURCE)
    if gap is not None:
        return (), ()

    gaps: list[ReadGap] = []

    # --- source 1: which vserver a certificate is bound to -----------------
    vserver_rows, vserver_gap = export.bindings(VSERVER_BINDING)
    bound: dict[str, set[str]] = {}
    if vserver_gap is None:
        shapes: set[str] = set()
        for row in vserver_rows:
            if not isinstance(row, dict):
                continue
            certkey = field_text(row, "certkeyname")
            vserver = field_text(row, "vservername")
            if certkey and vserver:
                bound.setdefault(certkey, set()).add(vserver)
                continue
            for field_name in ("certkeyname", "vservername"):
                shape = _field_gap(row, field_name, required=True)
                if shape is not None:
                    shapes.add(shape)
        if shapes:
            vserver_gap = ReadGap(
                source=VSERVER_BINDING,
                reason=(
                    _identity_shape_clause("een binding draagt certkeyname of vservername", shapes)
                    + "; die binding is niet te duiden, dus 'los' is voor"
                    " geen enkel certificaat meer te bewijzen uit deze bron"
                ),
            )
    if vserver_gap is not None:
        gaps.append(vserver_gap)

    # --- source 2: which certificate is bound through the cert-side binding
    # (to an sslservice/service, which VSERVER_BINDING above does not list).
    # Actually CONSUMED now, not just parsed and thrown away: a certkey that
    # appears here is referenced by this source, whether or not this pass
    # can also name what it is bound to.
    # Read in EITHER shape (`Export.binding_rows`), per child kind: on the
    # real collector output this file is 'aggregate', one document per
    # certificate. `binding_child_keys` names the kinds each document
    # carries, so a kind this version does not read is seen, not skipped.
    cert_grouped, cert_gap = export.binding_rows(CERT_BINDING, children=CERT_CHILDREN)
    unknown_kinds: dict[str, tuple[str, ...]] = {}
    if cert_gap is None:
        child_keys, cert_gap = export.binding_child_keys(CERT_BINDING)
    if cert_gap is None:
        for parent, keys in child_keys.items():
            other = tuple(key for key in keys if key not in CERT_CHILDREN)
            if other:
                unknown_kinds[parent] = other
    cert_rows = [row for pairs in cert_grouped.values() if pairs for _kind, row in pairs]
    cert_bound: dict[str, set[str]] = {}
    if cert_gap is None:
        shapes = set()
        for row in cert_rows:
            if not isinstance(row, dict):
                continue
            certkey = field_text(row, "certkey")
            if not certkey:
                shape = _field_gap(row, "certkey", required=True)
                if shape is not None:
                    shapes.add(shape)
                continue
            # A row that only NAMES a certificate here, with no
            # servicename/servername/vservername, is not evidence of use -
            # it is the shape the real fixture's own cert-side rows carry
            # for a certificate that is purely a link target (e.g. an
            # issuing CA), never bound to a service. Only a row that also
            # carries a target counts toward `gebonden`; a certkey with none
            # stays eligible for "los" (both sources read, neither binds it).
            target = _cert_binding_target(row)
            if target:
                cert_bound.setdefault(certkey, set()).add(target)
            else:
                # `_cert_binding_target` returns "" both when the row
                # carries NONE of the three target fields (the honest
                # zero-binding row above) and when one of them IS present
                # but not readable text - `field_text` collapses "absent"
                # and "present but unreadable" the same way, and `if
                # target:` above then treats both alike. Those are two
                # different facts: a row that carries no target
                # field at all proves nothing either way, but a row that
                # carries an unreadable target field PROVES the
                # certificate is referenced by this source, with only the
                # name of what it is bound to left unreadable - that is a
                # read gap, not grounds for "los". Ask each target field's
                # own shape here, independently of `_cert_binding_target`'s
                # collapsed "" (which stays out of scope, per the
                # constraints, unchanged): a field simply absent adds
                # nothing (the zero-binding row is unaffected), a field
                # present-but-unreadable adds its shape and, via `shapes`
                # below, turns this source into a read gap for every
                # certificate - the same "one bad row taints the whole
                # source" reasoning `vserver_gap` above already applies.
                for target_field in ("servicename", "servername", "vservername"):
                    target_shape = _field_gap(row, target_field)
                    if target_shape is not None:
                        shapes.add(target_shape)
        if shapes:
            cert_gap = ReadGap(
                source=CERT_BINDING,
                reason=(
                    _identity_shape_clause("een binding draagt certkey", shapes) + "; die binding is niet te duiden"
                ),
            )
    if cert_gap is not None:
        gaps.append(cert_gap)

    # --- the issuer relation: a certificate's own linkcertkeyname ----------
    issues: dict[str, set[str]] = {}
    link_shapes: set[str] = set()
    for row in certs:
        if not isinstance(row, dict):
            continue
        # `certkey`'s own shape gate runs on its own, BEFORE the identity
        # fallback below ever runs. Folding the fallback INTO the gate (the
        # old code computed `child` first and only asked about `certkey`'s
        # shape when `child` came out falsy) let a readable `name` hide a
        # present-but-unreadable `certkey`: `child` came out truthy from
        # `name` alone, so the
        # row's `certkey` never got asked for its shape, and a certificate
        # archived under its `name` - invisible to `bound`/`cert_bound`,
        # which are keyed on `certkeyname`/`certkey`, never `name` - read
        # as the favourable "los" with zero gaps, a regression from the
        # base this identity fallback was ported from. `required=False`:
        # a certificate identified only by `name`, with no `certkey` at
        # all, is a real, honest shape (`KEY_MISSING_TEXT`, via the
        # `not child` branch below, not here) - this check exists only to
        # catch `certkey` PRESENT but unreadable, independently of what
        # `name` does or does not carry.
        certkey_shape = _field_gap(row, "certkey")
        if certkey_shape is not None:
            link_shapes.add(certkey_shape)
        # Same identity expression the result loop below uses
        # (`field_text(row, "certkey") or field_text(row, "name")`, minus
        # its final "(naamloos)" placeholder fallback). Gating this row's
        # identity on `certkey` alone would let a row identified only by
        # `name` fail closed for no reason, and, worse, let a row with
        # NEITHER field silently drop its `linkcertkeyname` - the row's own
        # identity, not merely its issuer relation, is what would then be
        # unreadable there.
        child = field_text(row, "certkey") or field_text(row, "name")
        parent = field_text(row, "linkcertkeyname")
        if child and parent:
            # A certificate that names ITSELF as its own issuer is not an
            # issuing relationship: without this guard such a row escapes
            # both "los" and "onbekend" and sorts above them as "uitgever
            # van zichzelf".
            if child != parent:
                issues.setdefault(parent, set()).add(child)
            continue
        # `required=True`: an ABSENT identity here is not an honest "this
        # certificate has no issuer" - it means we cannot tell WHICH
        # certificate `linkcertkeyname` (if present) even names, so an
        # issuer relationship this pass cannot see could exist, and the
        # issuer it points at cannot be honestly cleared as "los" either.
        # Only `linkcertkeyname`'s own absence (the `else` branch, `child`
        # truthy) stays optional - most certificates have no issuer, and
        # that remains a real, honest statement.
        shape = _field_gap(row, "certkey", required=True) if not child else _field_gap(row, "linkcertkeyname")
        if shape is not None:
            link_shapes.add(shape)
    links_gap: ReadGap | None = None
    if link_shapes:
        links_gap = ReadGap(
            source=RESOURCE,
            reason=(
                _identity_shape_clause("een certificaat draagt certkey of linkcertkeyname", link_shapes)
                + "; de uitgifterelatie is daardoor niet volledig te lezen"
            ),
        )
        gaps.append(links_gap)

    # --- source 3: the use outside the bindings (`cert_usage`) --------------
    # A SAML action, a SAML IdP profile or an SSL servicegroup that names a
    # certificate uses it: such a certificate is `gebonden`, never `los`. A
    # reference from an object without a usable name still proves the use.
    # And `los` needs all three sources READ: a source this export does not
    # carry is "niet vastgesteld", never "no use".
    other = other_usage(export)
    gaps.extend(other.shared_gaps)
    gaps.extend(g.gap("een certificaat") for g in other.cert_gaps)
    elsewhere: dict[str, list[str]] = {}
    for use in other.uses:
        elsewhere.setdefault(use.certkey, []).append(use.label)
    referenced = set(elsewhere) | {g.certkey for g in other.cert_gaps}

    complete = vserver_gap is None and cert_gap is None and links_gap is None and other.complete

    result: list[Usage] = []
    for row in certs:
        if not isinstance(row, dict):
            continue
        name = field_text(row, "certkey") or field_text(row, "name") or "(naamloos)"
        if name in bound or name in cert_bound or name in referenced:
            # `used_by` carries ONLY names that
            # `disclosure.names_from_export()` demonstrably covers - the
            # vserver family, sourced from `bound` (VSERVER_BINDING's own
            # `vservername` field, the same field/source that family
            # reads). `cert_bound`'s names come from CERT_BINDING
            # (servicename/servername) - a source/field combination that
            # family does NOT collect, so surfacing them here broke the
            # fail-closed masking promise at 'beperkt'/'minimaal'. A
            # cert-side-only binding still proves `gebonden` (membership
            # via `name in cert_bound` above), just with no name attached.
            used = tuple(sorted(bound.get(name, set())))
            result.append(Usage(name, "gebonden", used, used_elsewhere=tuple(elsewhere.get(name, ()))))
        elif name in issues:
            result.append(Usage(name, "uitgever", tuple(sorted(issues[name]))))
        elif name in unknown_kinds:
            # A bound kind this version has no rule for is not proof of use,
            # and not proof of disuse either: `gebonden` and `uitgever` above
            # stay true statements, but `los` is exactly the claim this kind
            # could refute. Only THIS certificate is affected - the kind sits
            # in its own document.
            result.append(
                Usage(
                    name,
                    "onbekend",
                    (),
                    "niet vast te stellen of dit certificaat ergens aan hangt:"
                    f" {CERT_BINDING} draagt voor dit certificaat een bindingssoort die deze"
                    f" versie niet leest ({binding_kind_names(unknown_kinds[name])})",
                )
            )
        elif complete:
            result.append(Usage(name, "los"))
        else:
            unreadable = [
                source
                for source, failed in (
                    (VSERVER_BINDING, vserver_gap),
                    (CERT_BINDING, cert_gap),
                    (RESOURCE, links_gap),
                )
                if failed is not None
            ] + list(other.untrusted)
            parts = [f"{', '.join(unreadable)} niet te ontleden"] if unreadable else []
            if other.absent:
                parts.append(f"bron {', '.join(r.source for r in other.absent)} niet in de export")
            result.append(
                Usage(
                    name,
                    "onbekend",
                    (),
                    "niet vast te stellen of dit certificaat ergens aan hangt: " + "; ".join(parts),
                )
            )
    return tuple(result), tuple(gaps)


def usage_per_certificate(export) -> tuple[Usage, ...]:
    """The usage state of every certificate this export carries.

    See `_usage_and_gaps` for the full derivation. Public wrapper that
    drops the read gaps: `impact.py` (the other consumer of this function)
    carries its own read gaps on `ImpactAnswer.read_gaps`, built from its
    own reads - this function's gaps are `what_expires`'s to surface, via
    `_usage_and_gaps` directly, not a second copy here.
    """
    return _usage_and_gaps(export)[0]


def _impact_key(usage: Usage, days: int | None) -> tuple[int, int, str]:
    """Sort key: state first, then the shortest horizon, then the name.

    A certificate whose expiry could not be read sorts LAST within its state -
    an unknown number of days is not urgency, and pretending it is would
    reorder the list on a value that was never read.

    `_STATE_ORDER.get(...)` rather than `USAGE_WORDS.index(...)`: `Usage.state`
    is a free-form `str` on a public frozen dataclass, and `.index()` raises
    `ValueError` for anything outside the four known words - a crash in a
    read tool over a defensive-only case. A state this version does not
    recognize sorts last, after `onbekend`.
    """
    return (_STATE_ORDER.get(usage.state, len(USAGE_WORDS)), days if days is not None else 10**9, usage.certkey)


def _to_days(days) -> int | None:
    """Parses a raw daystoexpiration value into a whole number of days.

    A whole number in float form (14.0) simply counts as 14 - it is a
    number, not text, and the rule is that a NON-numeric value is
    unassessable, not that a numeric value in another format becomes so.
    A fractional part (14.7) is rounded down (`math.floor`): the threshold
    ladder below is monotonic in days, so rounding down never yields a less
    urgent class than the real, fractional number of days justifies (14.7
    becomes "critical", not the milder "warning" that rounding up would
    give). That is the same fail-closed choice as the rest of this function:
    when in doubt, do not alarm too late. Anything that truly is not a
    number (None, empty string, free text, NaN/infinity) yields None.
    """
    text = str(days).strip()
    try:
        return int(text)
    except (TypeError, ValueError):
        pass
    try:
        return math.floor(float(text))
    except (TypeError, ValueError, OverflowError):
        return None


def _classify(n: int) -> str:
    if n < 0:
        return "expired"
    if n <= THRESHOLDS["critical"]:
        return "critical"
    if n <= THRESHOLDS["warning"]:
        return "warning"
    if n <= THRESHOLDS["notice"]:
        return "notice"
    if n <= THRESHOLDS["horizon"]:
        return "horizon"
    return "ok"


def bucket(days) -> str:
    n = _to_days(days)
    return "unknown" if n is None else _classify(n)


def age_of(export, today: date | None = None) -> tuple[int | None, str | None]:
    """(age in days, None) of `export` on `today`, or (None, reason).

    `daystoexpiration` is the appliance's count AT THE SCAN. Every day the
    export ages, the real remaining time shrinks by one; the age comes from
    the same source as the data line under every answer
    (`export.collected_at`, through `answer.export_age`). `today` defaults
    to the UTC day, the frame that timestamp is in. A stub without the
    attribute has no date: that is a reason, never an age of zero.
    """
    return export_age(getattr(export, "collected_at", None), today if today is not None else datetime.now(UTC).date())


def remaining_days(raw, age_days: int | None) -> int | None:
    """Days left TODAY: `daystoexpiration` minus the age of the export.
    None when either side is unknown - never the raw field on its own."""
    days = _to_days(raw)
    if days is None or age_days is None:
        return None
    return days - age_days


def bucket_from_today(raw, age_days: int | None) -> str:
    """`bucket` on the corrected count; "unknown" when it cannot be made."""
    n = remaining_days(raw, age_days)
    return "unknown" if n is None else _classify(n)


def counted_from_today(age_days: int) -> str:
    """The clause every dated expiry line carries."""
    return f"gerekend vanaf vandaag, export van {age_days} {'dag' if age_days == 1 else 'dagen'} oud"


def what_expires(export, knowledge: Knowledge, horizon_days: int, *, today: date | None = None) -> Answer:
    """The certificates that expire within `horizon_days` FROM TODAY.

    `daystoexpiration` counts from the scan; it is corrected for the age of
    the export (`age_of`) before the horizon, the class and the sort see
    it. An export whose date is not readable gives every certificate with
    a numeric field `niet vastgesteld`: the raw field is never shown as if
    it counted from today."""
    age_days, age_reason = age_of(export, today)
    certs, gap = export.objects(RESOURCE)
    read_gaps: list[ReadGap] = [gap] if gap else []
    findings: list[Finding] = []

    usages, usage_gaps = _usage_and_gaps(export)
    usage = {u.certkey: u for u in usages}
    read_gaps.extend(usage_gaps)

    rows: list[tuple[tuple[int, int, str], Finding]] = []
    for c in certs:
        name = field_text(c, "certkey") or field_text(c, "name") or "(naamloos)"
        raw = c.get("daystoexpiration")
        scan_days = _to_days(raw)
        days = remaining_days(raw, age_days)
        state = usage.get(name, Usage(name, "onbekend", (), "geen gebruiksstand berekend"))
        if state.state == "gebonden" and state.used_elsewhere:
            bound_to = f" aan {', '.join(state.used_by)}" if state.used_by else ""
            detail = f" - gebonden{bound_to}; gebruikt door {', '.join(state.used_elsewhere)}"
        elif state.state == "gebonden" and state.used_by:
            detail = f" - gebonden aan {', '.join(state.used_by)}"
        elif state.state == "uitgever":
            detail = f" - uitgever van {', '.join(state.used_by)}"
        else:
            detail = f" - {state.state}"
        # publickeysize arrives as a JSON integer, not text - field_text()
        # returns "" for any non-string on purpose (see tls_baseline.py's
        # own note on this), so field_token() is the one that reproduces it
        # as displayable text; the isdigit() gate keeps a malformed or
        # multi-value form out of this evidence line entirely (an ungated
        # field embedded verbatim in a rendered line is exactly the defect
        # class this closes).
        key_size = field_token(c, "publickeysize")
        key_size = key_size if key_size.isdigit() else "onbekend"
        # signaturealg must not go into key_bits UNGATED - field_text()
        # guarantees only "a stripped string", not "short and single-line".
        # A newline in this field would render as a second, fabricated
        # finding line. _signature_text() is the shape gate: the SAME
        # treatment publickeysize gets one line up.
        signature = _signature_text(c)
        key_bits = f"sleutel {key_size} bits, {signature}"
        if scan_days is not None and days is None:
            # A numeric field, but no readable export date: how many of those
            # days are already gone is not known. Fail-closed - listed
            # whatever the horizon, never filtered on the scan's count.
            rows.append(
                (
                    _impact_key(state, None),
                    Finding(
                        subject=name,
                        outcome=f"vervaldatum vanaf vandaag niet vast te stellen{detail}",
                        certainty=Certainty.NOT_ESTABLISHED,
                        evidence=f"{RESOURCE}: daystoexpiration telt vanaf de scan; {key_bits}",
                        reason=(
                            f"de leeftijd van de export is niet vast te stellen ({age_reason}); hoeveel"
                            " dagen sinds de scan al verstreken zijn is daarmee onbekend"
                        ),
                    ),
                )
            )
            continue
        if days is None:
            # daystoexpiration is verdict-, level- AND sort-steering - a
            # gated field, per the constraints. Present-but-unreadable is
            # NOT VASTGESTELD met de VORM benoemd (`shape_of`), never the
            # real value: `raw!r` would echo a dict or list in full at
            # 'volledig'/'beperkt'.
            rows.append(
                (
                    _impact_key(state, None),
                    Finding(
                        subject=name,
                        outcome=f"vervaldatum niet vast te stellen{detail}",
                        certainty=Certainty.NOT_ESTABLISHED,
                        evidence=f"{RESOURCE}: daystoexpiration={shape_of(raw)}; {key_bits}",
                        reason="daystoexpiration ontbreekt of is niet numeriek; de appliance zelf zou hier ook zwijgen",
                    ),
                )
            )
            continue
        if days > horizon_days:
            continue
        level = _classify(days)
        outcome = "is verlopen" if days < 0 else f"verloopt over {days} dagen ({level})"
        rows.append(
            (
                _impact_key(state, days),
                Finding(
                    subject=name,
                    outcome=f"{outcome}{detail}",
                    certainty=Certainty.ESTABLISHED,
                    # The corrected day count is already in `outcome` above; the
                    # evidence names how it was counted.
                    evidence=f"{RESOURCE}: {key_bits}; {counted_from_today(age_days)}",
                    reason=state.reason,
                    days_left=days,
                    expired=days < 0,
                ),
            )
        )
    findings = [finding for _key, finding in sorted(rows, key=lambda item: item[0])]
    if not findings and gap is None:
        # Nothing within the horizon is a finding about a source that WAS
        # read, so it gets a sentence, never an empty list the reader has to
        # interpret. Never said over an unread source: then `gap` stands.
        read = f"{len(certs)} {'certificaat' if len(certs) == 1 else 'certificaten'} gelezen"
        findings.append(
            Finding(
                subject="certificaten",
                outcome=f"geen certificaat verloopt binnen {horizon_days} dagen ({read})",
                certainty=Certainty.ESTABLISHED,
                evidence=RESOURCE if age_days is None else f"{RESOURCE}; {counted_from_today(age_days)}",
                subject_is_name=False,
            )
        )

    return Answer(
        question=f"wat verloopt er de komende {horizon_days} dagen",
        findings=findings,
        read_gaps=read_gaps,
        # A source of the use outside the bindings that this export does not
        # carry is a boundary of the list: "niet vastgesteld", never "no use".
        not_assessed=[NOT_ASSESSED_USAGE, *absent_dimensions(export)],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
