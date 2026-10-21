"""The disclosure knob: how much the answer reveals to the model reading along.

Second axis next to the profile (profile = network posture; disclosure = what
the TEXT may reveal). Design and ladder: docs/ARCHITECTURE.md.

Three hard rules from that design:
1. The filter is COMPUTED, never performed by the model - the model is
   precisely the thing being shielded against.
2. The filter lives on the envelope boundary: the analysis does not change,
   only the presentation. Parity between the levels holds by construction.
3. The pseudonym table follows the credential discipline: the reference (the
   pseudonym) reaches the model, the value (the real name) only the
   operator's disk.

The product carries the seam plus a PRESET of the levels; configuring it per
customer environment (which level, what counts as sensitive) is out of scope.

Two structural choices to know before editing:
- Name collection is STRUCTURAL: it comes from the export - the source that
  knows the name of every appliance object, regardless of which text field
  that name later ends up in - not (only) from the answer, which happens to
  contain only what the asked question needed. See `names_from_export()` and
  `_limit()`.
- A broken or suspicious pseudonym table is refused fail-closed: never a
  silent self-repair, never an overwrite, and no refusal message ever carries
  literal table content. See `PseudonymTableBroken`, `_validate_loaded_table`
  and `_entry_ref`.
- Caller INPUT is not a name of this appliance and never enters the name
  collection. It used to, and that was a measured defect with three faces:
  a healthy table accused of being broken (with the harmful advice to set it
  aside), any question blockable with a single letter, and client-side growth
  of the operator's table. See `_collect_names()` for the mechanism and
  `render()` for where origin is decided. The one input that is still refused
  - a pseudonym this server issued itself - has its own honest message:
  `PseudonymAsInput`.
"""

from __future__ import annotations

import json
import msvcrt
import os
import re
import threading
import time
from dataclasses import replace
from enum import Enum
from pathlib import Path

from nsmcp.answer import NAME_CUT_NOTE, Answer, Certainty
from nsmcp.cert_usage import names_in_cert_usage_sources
from nsmcp.chain import ENTRY_RESOURCES, NOT_FOLLOWED, SERVICEGROUP_BINDING, names_in_chain_sources
from nsmcp.compare import names_in_compare_sources
from nsmcp.coverage import names_in_coverage_sources
from nsmcp.cve import names_in_predicate_sources
from nsmcp.dienst import names_in_service_sources
from nsmcp.errors import ToolError
from nsmcp.expiry import CERT_BINDING, RESOURCE as _CERT_RESOURCE
from nsmcp.export import TARGET_NAME_REFUSED
from nsmcp.ha import names_in_ha_sources
from nsmcp.headers import names_in_header_sources
from nsmcp.hidden_rules import names_in_hidden_rule_sources
from nsmcp.impact import BINDING_FILE
from nsmcp.limits import NAME_ECHO_MAX_LEN
from nsmcp.mgmt_plane import names_in_mgmt_sources
from nsmcp.names import names_in_name_sources
from nsmcp.overzicht import names_in_overview_sources
from nsmcp.tls_baseline import names_in_tls_sources


class Disclosure(Enum):
    FULL = "volledig"
    LIMITED = "beperkt"
    MINIMAL = "minimaal"


# The aggregate by-parent files a tool READS and prints names out of, for the
# fifteenth family of `names_from_export()`: the loadbalancing entry file of
# `dienst_keten` (the entry kinds it does not follow are left out), the
# servicegroup file of `dienst_keten` and `status_gezondheid`, and the
# certificate-side file of the certificate tools. Derived from the modules
# that read them, so a chain that starts following another entry kind is
# masked the day it does.
AGGREGATE_BINDING_FILES = (
    *(binding_file for kind, _resource, _key, binding_file in ENTRY_RESOURCES if kind not in NOT_FOLLOWED),
    SERVICEGROUP_BINDING,
    CERT_BINDING,
)


# The closing "doel: ..." line at `minimaal` for a RECORDED target - see
# `_minimal()`. Never a pseudonym: one value, one mapping, no information
# hidden by masking it that way.
_TARGET_NOT_SHOWN_AT_MINIMAL = "niet getoond op deze stand"


def load_disclosure(value: str) -> Disclosure:
    """Unknown refuses - same discipline as load_profile: a typo must never
    silently yield a different disclosure level than the operator meant."""
    clean = str(value).strip().lower()
    for level in Disclosure:
        if level.value == clean:
            return level
    valid = ", ".join(s.value for s in Disclosure)
    raise ValueError(f"onbekende openheid {value!r}; geldig is: {valid}")


def _readable_name(value) -> str | None:
    """Same discipline as impact.py's `_readable_name`: only real text counts
    as a name. A list/dict/number/boolean/None is never blindly stringified
    here (that would be a silent distortion, not a name) - the isinstance
    gate sits BEFORE the normalization, just like there."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def names_from_export(export) -> tuple[str, ...]:
    """The STRUCTURAL name collection. Not the answer - which happens to
    contain only what the asked question needed - but the export itself,
    which knows the name of every appliance object, regardless of which text
    field of which answer that name ever ends up in.

    Seventeen families, each read at exactly the place and field where the
    analysis modules read them too (expiry.py/impact.py/cve.py/dienst.py/
    chain.py stay unchanged - this file only IMPORTS their public RESOURCE/
    BINDING_FILE constants and cve.py's/dienst.py's/chain.py's own
    derivations, it repeats no copy of those literal names):
    - certkey names: `export.objects(RESOURCE)` ("config/sslcertkey"), field
      "certkey" (the same primary field that expiry.py reads).
    - vserver names: `export.bindings(BINDING_FILE)`, field "vservername"
      on every binding entry (the same field that impact.py reads).
    - parent-object names: `export.binding_parents(BINDING_FILE).names` -
      the objects the binding file's parent list is cross-checked against.
      This third family was added together with that cross-check and is not
      optional decoration: the gap it reports NAMES the service whose
      bindings were never read, and such a service appears in neither family
      above (it has no binding entry - that is the whole point - and it is
      not a certificate). Without this line the very repair that makes a
      missing service VISIBLE would make its name LEAK in this setting.
    - condition-source names: `cve.names_in_predicate_sources(export)` - the
      Gateway/AAA vservers and the SAML/LSN objects the CVE conditions name
      in their evidence. See the comment at that call below for the
      measurement that showed the other three families cover them only by
      accident.
    - service names: `dienst.names_in_service_sources(export)` - every name
      `dienst_status` can PRINT or ACCEPT: the lbvserver names, the
      servicegroups bound to them, and each member by server name or by IP.
      See the comment at that call below for the measurement:
      without this family a genuinely known dienst name was misclassified
      as caller-invented at the disclosure seam and rendered as "onbekende
      naam uit de vraag" - never a literal leak (finding.subject already
      covers the text itself), but a false "unknown" about a name this
      export does know. Reading only the lbvserver names left that same
      false claim standing for a real servicegroup or a real member, which
      a caller may just as well type into `dienst`.
    - HA node names: `overzicht.names_in_overview_sources(export)` - every
      name `status_overzicht` can print. See the comment at that call below
      for the measurement: the HA node name sits in the
      "HA" finding's evidence and, on the real export, is known to none of
      the five families above.
    - binding-parent names of EVERY by-parent file:
      `coverage.names_in_coverage_sources(export)` - every parent-object
      name `rapport_dekking` can print in a cross-check gap. See the
      comment at that call below for the measurement: the third family
      above reads only ONE binding file (impact.BINDING_FILE), and the
      other six are cross-checked against object sources of their own -
      config/sslprofile among them, which no family above reads.
    - the names `status_namen` prints per family:
      `names.names_in_name_sources(export)` - the loadbalancing,
      contentswitching and Gateway vservers, the servicegroups, the services
      and the certificates. This is the one tool that prints entity names on
      purpose, so a name it can print and this function does not collect
      leaks by design rather than by accident. See the comment at that call
      below for the measurement: the fourth family covers most of the same
      resources, but not the same FIELDS.
    - the HA node names of the `ha` chapter: `ha.names_in_ha_sources(export)`
      - every name `ha_stand` could print. See the comment at that call
      below: this family adds no name on the real export (the sixth family
      reads the same resource), and it exists so that a later version of
      ha.py which DOES name a node cannot leak one because the family was
      forgotten.
    - management-plane names: `mgmt_plane.names_in_mgmt_sources(export)` -
      the nsip addresses, command-policy names, system user name(s), the
      vservers carrying the default management certificate and that
      certificate's own name. See the comment at that call below for what
      overlaps with earlier families and what does not.
    - aggregate binding names: `export.binding_names(AGGREGATE_BINDING_FILES)`
      - every parent name and identity field of the aggregate by-parent
      files the tools read. See the comment at that call below for the
      measurement.
    - certificate-use names: `cert_usage.names_in_cert_usage_sources(export)`
      - the SAML actions, SAML IdP profiles and SSL servicegroups that name a
      certificate outside the bindings with virtual servers.
    - compared reference names: `compare.names_in_compare_sources(export)`
      - the object a compared field names (`compare.REFERENCE_FIELDS`), also
      when that object is absent from the export. See the comment at that
      call below for the measurement.

    FAIL-CLOSED by construction, no separate rule: `objects()`/`bindings()`
    simply return an empty list on a read gap (see export.py), and this
    function reads that result as-is. An unreadable source therefore yields
    FEWER names here by itself, never an error or a guess. That is safe, not
    incomplete: a name the export could not read can also never appear in an
    answer text (the engine simply never knew it, so it could not write it
    into an outcome/evidence/read-gap source either) - so nothing that needs
    replacing is missed here.

    The placeholder "(naamloos)" - the honest fallback of impact.py/
    expiry.py when a name is missing - is deliberately NOT collected: it is
    not an object name but a "no name known" statement, and as a pseudonym
    it would make a MISSING name look like a real object.
    """
    names: set[str] = set()

    cert_objects, _ = export.objects(_CERT_RESOURCE)
    for o in cert_objects:
        if not isinstance(o, dict):
            continue
        name = _readable_name(o.get("certkey"))
        if name and name != "(naamloos)":
            names.add(name)

    bindings, _ = export.bindings(BINDING_FILE)
    for b in bindings:
        if not isinstance(b, dict):
            continue
        name = _readable_name(b.get("vservername"))
        if name and name != "(naamloos)":
            names.add(name)

    # Read through the SAME derivation impact.py uses for its read gap (one
    # source, two consumers), so the collection here and the names in that
    # gap text can never drift apart. `getattr` with a fail-closed empty
    # default: an export layer without this method is an older or stubbed
    # one, which then also produces no such gap and thus no such name.
    parent_names = getattr(export, "binding_parents", None)
    if parent_names is not None:
        for name in parent_names(BINDING_FILE).names:
            clean = _readable_name(name)
            if clean and clean != "(naamloos)":
                names.add(clean)

    # Fourth family: the objects the CVE conditions name in their evidence -
    # Gateway/AAA vservers, and the SAML/LSN objects out of the running
    # config. MEASURED (2026-09-02): on the live fixture those Gateway
    # vservers happen to be ssl-vservers with a certificate binding too, so
    # the families above knew them BY ACCIDENT; a Gateway without such a
    # binding, and every SAML action, is known to none of them - and the
    # condition evidence writes exactly that name into the answer. Read
    # through cve.py's own derivation (one source, two consumers), so the
    # collection here and that evidence can never drift apart.
    for name in names_in_predicate_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Fifth family: every name `dienst_status` can print or accept - the
    # lbvserver, its servicegroups, and each member by server name or by IP.
    # Read through dienst.py's own derivation (one source, two consumers),
    # for the same reason as the fourth family above. That derivation
    # harvests deliberately more tolerantly than the analysis reads: a read
    # gap there NAMES a parent ("dubbele parent X", "servicegroup X
    # ontbreekt..."), so a harvest that fell silent on an unusable file
    # would leak exactly the name the repair makes visible.
    for name in names_in_service_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Sixth family: the HA node name(s) `overview()` writes into the "HA"
    # finding's evidence (config/hanode). MEASURED (2026-09-02, on the real
    # export tests/fixtures/lab-export-vpx-20260826): that name
    # ("host-006.lab.example") is neither a certkey, an sslvserver binding, a
    # binding-parent name, a Gateway/AAA/SAML/LSN predicate name, nor an
    # lbvserver/servicegroup/member name, so it sat in none of the five
    # families above and leaked verbatim in the 'beperkt' setting before this
    # family existed. Read through overzicht.py's own derivation (one
    # source, two consumers), same reason as the fourth and fifth families.
    for name in names_in_overview_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Seventh family: the parent-object names of EVERY by-parent binding file
    # in this manifest. `rapport_dekking` reports a cross-check gap per file,
    # and such a gap NAMES the object whose bindings were never read.
    # MEASURED (2026-09-06, on tests/fixtures/lab-export-vpx-20260826): six of
    # the seven binding files carried such a gap before the aggregate files
    # were cross-checked (four since). The three that name VSRV-001
    # all derive it from config/sslvserver, which the third family above
    # already reads, so that name is NOT what this family repairs. What it
    # adds is the parent list of a file whose object source no other family
    # reads - sslprofile_sslcipher_binding.by-parent.json against
    # config/sslprofile. That file has no gap on THIS export, so those names
    # are collected and never used today - and they are NOT free: this
    # function's result is `extra_names` for EVERY tool, so those nine
    # vendor-default names are pseudonymised in every tool's output at
    # `beperkt` and `minimaal` and land in the operator's pseudonym table.
    # That cost is accepted deliberately: a name too few is a leak, a name
    # too many is a table entry to look past. Read through coverage.py's
    # own derivation (one source, two consumers), same reason as the fourth,
    # fifth and sixth families.
    for name in names_in_coverage_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Eighth family: every name `status_namen` prints. That tool prints entity
    # names ON PURPOSE and UNCONDITIONALLY, which makes this the one family
    # that is load-bearing by design rather than by an edge case: a name it
    # can print and this function does not collect leaks verbatim at
    # `beperkt` and `minimaal`.
    #
    # MEASURED (2026-09-06) and it corrects the expectation this was built on:
    # the fourth family already reads FIVE of the six resources of
    # names.FAMILIES through its reference rules, and the sixth is the first
    # family - so on tests/fixtures/lab-export-vpx-20260826 this family adds
    # no name at all. Where it DOES matter is where the FIELDS diverge:
    # `status_namen` prints a servicegroup by `servicegroupname`, the cve
    # harvest lands on `name`, and a row carrying both prints one and masks
    # the other. Proven end to end in tests/test_names.py on a synthetic
    # export. Beyond that one shape it is the drift guard: this is the only
    # family that reads through names.py's OWN derivation (one source, two
    # consumers), so a seventh line in that table is masked the day it is
    # added instead of depending on cve.py happening to cover it.
    for name in names_in_name_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Ninth family: the HA node names of the `ha` chapter. Today `ha_state()`
    # prints counts and words and no node name at all - pinned by
    # tests/test_ha.py, which proves the PREMISE (the name really is in this
    # export and really is collected here) before asserting its absence from
    # the answer. On tests/fixtures/lab-export-vpx-20260826 this family
    # therefore adds nothing the sixth family does not already read: both
    # harvest `config/hanode`. It exists so that a later version of ha.py
    # which DOES name a node ("rij 1" is one small step from the name) cannot
    # leak one because nobody remembered to add the family. Read through
    # ha.py's own derivation (one source, two consumers), same reason as the
    # fourth through eighth families.
    for name in names_in_ha_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Tenth family: the instances the hidden rules print - including nsip
    # ADDRESSES, which no family above harvests. MEASURED on the real export:
    # NSHC-HR-MGMT-001 and -MGMT-003 name three management addresses
    # verbatim. Read through hidden_rules.py's own derivation, so a rule added
    # tomorrow is covered without a second list here.
    for name in names_in_hidden_rule_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Eleventh family: the sslvserver names this grade prints and the SSL
    # profile names that appear in its `bron:` field. MEASURED: VSRV-001 has no
    # certificate binding at all, so the certificate families know it only by
    # accident, and a custom profile name is known to none of them.
    for name in names_in_tls_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Twelfth family (A7): the nsip addresses, command-policy
    # names, system user name(s) and the vservers carrying the default
    # management certificate that `beveiliging_beheervlak` can print, plus
    # that certificate's own name (printed UNCONDITIONALLY in both its PASS
    # and its FAIL reason text, not only when the tenth family's
    # NSHC-HR-SSL-001 happens to fire on the same export). The nsip addresses
    # overlap with the tenth family (hidden_rules); a system USER name and a
    # command-policy name appear in NO other family. Read through
    # mgmt_plane.py's own derivation, same reason as the fourth through
    # eleventh families.
    for name in names_in_mgmt_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Thirteenth family (A9): every link a chain prints. The
    # entry points overlap with the names family, but a MEMBER by server
    # name or by IP inside a servicegroup binding that `dienst_status` never
    # touched appears in no other family. Read through chain.py's own
    # derivation, same reason as the fourth through twelfth families.
    for name in names_in_chain_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Fourteenth family: vserver names that the header analysis can print as
    # binding evidence. Read through headers.py's own derivation so masking
    # follows the same field choices as the answer.
    for name in names_in_header_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Fifteenth family: every parent name and identity field of the
    # AGGREGATE by-parent files the tools read (`Export.binding_names` over
    # `AGGREGATE_BINDING_FILES`). The chain, the certificate tools and the
    # health snapshot print names out of them: a service a certificate is
    # bound to, a servicegroup, a member. MEASURED on a workbench export in
    # the aggregate shape before this family existed (the synthetic
    # tests/fixtures/lab-export-vpx-doh-synthetic carries the same shape):
    # the eight service names bound to ns-server-certificate and one service
    # address were in none of the fourteen families above. Deliberately NOT
    # every aggregate file: see `Export.binding_names` for the built-in
    # monitor names that garbled ordinary words. `getattr` with a fail-closed
    # empty default, the same reason as the third family: an export layer
    # without this method is an older or stubbed one.
    binding_names = getattr(export, "binding_names", None)
    if binding_names is not None:
        for name in binding_names(AGGREGATE_BINDING_FILES):
            clean = _readable_name(name)
            if clean and clean != "(naamloos)":
                names.add(clean)

    # Sixteenth family: the objects outside the bindings with virtual
    # servers that name a certificate - SAML actions, SAML IdP profiles and
    # SSL servicegroups - which the certificate tools print as the user of a
    # certificate. A SAML action is known to the fourth family only through
    # the running config, and an SSL servicegroup name out of its own binding
    # file to none of them. Read through cert_usage.py's own derivation (one
    # source, two consumers), same reason as the fourth through fifteenth
    # families.
    for name in names_in_cert_usage_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Seventeenth family: the names a compared REFERENCE field carries - the
    # default LB vserver of a csvserver (`targetlbvserver`), the issuer
    # certificate of a certificate (`linkcertkeyname`). `rapport_vergelijk`
    # and `rapport_wat_is_er_veranderd` print both values of such a field
    # when they differ. MEASURED on a synthetic pair whose referenced LB
    # vserver and issuer certificate are absent from the export: the four
    # names were in none of the sixteen families above and reached both
    # tools' answers verbatim at 'beperkt'. A reference to an object that IS
    # in the export was masked already, through that object's own family.
    # Read through compare.py's own table and derivation (one source, two
    # consumers), same reason as the fourth through sixteenth families.
    for name in names_in_compare_sources(export):
        clean = _readable_name(name)
        if clean and clean != "(naamloos)":
            names.add(clean)

    # Not one of the seventeen families counted above (this docstring's own
    # count, and `tests/test_disclosure.py`'s): the export's OWN target name
    # (`scan-doel.txt` line 1, `Export.target_name`) is not an appliance
    # OBJECT like the twelve families are - it is the appliance the export
    # was taken FROM - but `answer.stamp_data()` puts it verbatim in the
    # closing "doel: ..." line of EVERY answer at EVERY disclosure level, so
    # it needs the same seam. MEASURED: at `minimaal`,
    # where every other name is gone, this one still stood there.
    # `TARGET_NAME_REFUSED` is excluded - that is the boundary gate's own
    # fixed refusal phrase, not a name, and pseudonymising it would dress an
    # honest refusal up as a known object.
    target = _readable_name(getattr(export, "target_name", None))
    if target and target != TARGET_NAME_REFUSED:
        names.add(target)

    # Sorting here is only for determinism of this function itself (a stable
    # return value for tests); `_collect_names()` below reorders by length
    # for the masking order anyway.
    return tuple(sorted(names))


def _collect_names(answer: Answer, extra_names: tuple[str, ...], invented_name: str | None = None) -> list[str]:
    """The object names that must be replaced. The main body comes from
    `extra_names` - which, from mcp_server.py, carries the output of
    `names_from_export()` (the STRUCTURAL source, see there). What comes out
    of the answer itself (finding.subject, affected_vservers,
    issued_certificates) remains next to it as a SECOND net: a name the
    caller already knew via the export
    should arrive through that route too, but should `extra_names` ever be
    empty (a caller not following the structure), this product does not fall
    straight back to zero protection.

    Deliberately NOT excluded: ReadGap.source. It was once listed here
    separately with the reasoning "a resource path such as config/sslvserver,
    not an object name" - true for export.py, but WRONG for impact.py
    (`source=f"...vservername={value}"`, the per-binding read-gap report)
    and action.py (which puts a finding subject, a vserver name, straight
    into the source) - exactly the fail-closed paths this product
    advertises. `_limit()` below therefore replaces EVERY text field,
    including `ReadGap.source`: a resource path contains none of the
    collected names, so the replacement is a no-op there and thus harmless;
    for a read gap with a name in it, that same replacement is essential.

    The placeholder "(naamloos)" (the honest fallback of impact.py/expiry.py
    when a name is missing) is explicitly removed here, should it arrive via
    finding.subject, affected_vservers or issued_certificates - otherwise an
    ABSENT name gets a pseudonym, making a missing object look like a real
    one.

    `invented_name` is removed for a related but sharper reason, and it is
    the repair of a MEASURED defect (2026-08-27; the analysis behind it sits
    in `PseudonymAsInput`). It is the name the CALLER supplied while the
    export does not know it - so it is not an appliance object, and this
    collection is exclusively about appliance objects. Letting it in anyway
    treated caller INPUT as a REAL NAME, with two proven consequences:

    - it went into `_validate_loaded_table()` as a real name and was tested
      there against every pseudonym key with `_collides_with_real_names()`
      (equality AND substring, both directions). The single letter "b"
      therefore collides with "object-01" - so ANY question in the LIMITED
      setting could be blocked with trivial input, and the operator was told
      their table was broken and could be set aside. That advice destroys
      the only key to the real names. This is an AVAILABILITY defect, not a
      wording defect;
    - a name that did not collide got a fresh pseudonym and was written to
      the operator's table as a permanent row - client-side growth of the
      most sensitive file the customer has.

    The repair is this removal, deliberately NOT a relaxation of the
    collision test: that test (one shared predicate for generator and
    validator, equality and substring, both directions) is exactly what
    keeps the pseudonym namespace clean and stays untouched. The input has
    to stay out; the test does not have to give way. It follows that the
    invented name also gets no pseudonym in the rendered text - see
    `_limit()` for what that means for the answer, and `render()` for the
    one case that is refused instead.
    """
    # Only the subjects that ARE appliance object names. A finding declares
    # that with `Finding.subject_is_name` (answer.py, default True, so an
    # unflagged finding keeps the old fail-closed behaviour). cve.py and
    # overzicht.py flag theirs False: "build", "HA", the vserver family
    # labels, "CVE-oordeel" and the bulletin/CVE identifiers are this
    # product's own vocabulary and public identifiers, not objects on the
    # customer's appliance - masking them cost the reader the answer and
    # wrote them into the operator's pseudonym table as real names. `getattr`
    # with the same fail-closed default as the two collections below, for a
    # caller-built answer object that predates the field.
    names: set[str] = {b.subject for b in answer.findings if getattr(b, "subject_is_name", True)}
    names.update(getattr(answer, "affected_vservers", ()) or ())
    # The SECOND explicit collection an ImpactAnswer carries: the
    # certificates this certificate issues. Same `getattr` guard and the same
    # reason as the line above it - a rename of the field must not silently
    # fall back to zero, and this collection may hold a real object name the
    # question itself never mentioned.
    names.update(getattr(answer, "issued_certificates", ()) or ())
    # The THIRD explicit collection an ImpactAnswer carries: the certificate
    # names that carry a half name the caller typed (`impact.what_breaks`).
    # Same `getattr` guard and the same reason as the two lines above it, and
    # the same "or ()" - here that also covers the None state, which on this
    # field means "no candidate question" rather than "no candidates" (see
    # `impact.ImpactAnswer`). MEASURED with `extra_names=()` before this line
    # existed: the candidate line kept two real certificate names minus the
    # caller term ("...erver-certificate"), a partial leak.
    names.update(getattr(answer, "name_candidates", None) or ())
    # The FOURTH explicit collection: the SSL services on the questioned
    # certificate, read from the certificate-side binding file. Same `getattr`
    # guard and the same reason as the collections above.
    names.update(getattr(answer, "affected_services", ()) or ())
    # The FIFTH: the uses outside the bindings - the SAML action, SAML IdP
    # profile or SSL servicegroup that names the certificate. Structured, so
    # the object name is taken from its own field, never from a sentence.
    names.update(u.owner for u in getattr(answer, "other_uses", ()) or () if isinstance(getattr(u, "owner", None), str))
    names.update(n for n in extra_names if str(n).strip())
    names.discard("(naamloos)")
    if invented_name:
        # Also via finding.subject: `what_breaks()` puts the asked certnaam
        # in there, so removing it from `extra_names` alone would not be
        # enough - it would simply come back in through the answer.
        names.discard(invented_name)
    # Descending by length - the masking lesson: a shorter name sitting
    # inside a longer one must never break the longer match.
    return sorted((n for n in names if n.strip()), key=len, reverse=True)


class PseudonymTableBroken(ToolError):
    """The pseudonym table exists, but can no longer be read as a JSON object.

    ToolError subclass (not a bare ValueError): this is an INTENDED refusal
    the operator must see with its own text, just like the identity and
    refusal errors elsewhere in the product (see the error masking in
    mcp_server.py). Without this class relation the generic masking would
    replace this error with "onverwachte fout, de details zijn niet
    bewaard" - exactly the text that must NOT appear here, because the path
    and the recovery suggestion are the useful part of the message.

    FLIP SIDE of that class relation: because this message reaches the AI
    client UNMASKED, it must never carry literal table content (keys or
    values) - a suspicious entry is often precisely a real name. Every raise
    site therefore points at entries by position (`_entry_ref()`) and at the
    reason category, never at the content itself.
    """


class PseudonymTableLocked(ToolError):
    """1.0.2: the lock next to the pseudonym table could not be taken -
    it could not be opened (measured in the review: a DIRECTORY at the lock
    path gave a PermissionError) or another process kept it past the time
    limit. A ToolError, so the operator reads WHY; it used to reach the
    model as the generic "Onverwachte fout". Names the lock path (the
    operator's own configuration) and never table content."""


class PseudonymSpaceExhausted(ToolError):
    """`_next_free_pseudonym()` could not find a free candidate within
    `_MAX_PSEUDONYM_ATTEMPTS` tries.

    MEASURED: `_collides_with_real_names()`
    tests a candidate as a SUBSTRING of a real name in EITHER direction, so
    a real name that is itself a substring of the fixed literal prefix
    "object-" (any of "o", "b", "j", "e", "c", "t", "-", or a combination -
    an entirely ordinary one-character appliance object name, or a
    correctly typed `extra_names=("o",)`, both qualify) collides with EVERY
    candidate this generator could ever produce. Incrementing the number
    changes nothing, because the colliding part of the candidate is the
    fixed prefix, not the number - so the old `while True` never returned
    (measured: `render(..., extra_names=("o",))` hangs, faulthandler stack
    ending in `_next_free_pseudonym`). `mcp_server._write_names()`'s
    allowlist type check closes exactly
    ONE calling path that could hand such a name to this generator - the
    ONLY place a bug can truly be closed is HERE, in the generator itself,
    which is what this class and the bound in `_next_free_pseudonym()`
    exist for.

    ToolError subclass, same reasoning as `PseudonymTableBroken`: an
    INTENDED refusal the operator must see with its own text, not the
    generic "onverwachte fout" replacement - and the same flip side, too:
    this message never carries the literal colliding name. A name that
    collides with the fixed "object-" prefix is typically short and
    ordinary (a single letter is enough), and echoing it here would add
    nothing a diagnosis needs while breaking the same discipline every
    other refusal in this module already keeps.
    """


class PseudonymAsInput(ToolError):
    """The question was asked with a name the CALLER supplied that carries
    the shape of a pseudonym - a reference this setting cannot resolve.

    The measured case (2026-08-27, a real stdio MCP session against the VPX
    lab): in the LIMITED setting only ANSWERS are pseudonymized; the
    `certnaam` INPUT is merely stripped. A client that saw `object-11` in an
    earlier answer and asks on with it used to hand that pseudonym straight
    to `_collect_names()`, where it joined the collection of REAL names -
    and there it collided with its own assigned value in the table.

    That root cause is gone (see `_collect_names()`: caller input no longer
    enters the collection at all, so it can no longer accuse a healthy table
    nor grow it). What remains is the question this class answers: a
    pseudonym is a reference to a real object, and this setting cannot
    resolve it. Answering anyway would mean reporting "geen gebonden
    virtuele servers gevonden" about a certificate that may well carry
    several - a false green on precisely the question the operator asked. So
    this stays a REFUSAL, fail-closed, no answer and no guess.

    What changes is the DIAGNOSIS. The old message named the path and told
    the operator to "herstel het bestand of zet het aan de kant", while the
    table was demonstrably healthy (proven in the same measurement: a repeat
    run with the real names produced byte-identical answer text). Setting
    that table aside would shift every pseudonym and break the link with
    every earlier report - real damage from wrong advice.

    A SIBLING of PseudonymTableBroken, deliberately not a subclass: the two
    must stay distinguishable, and every existing test that catches a broken
    table must not accidentally catch this one too. Same ToolError relation
    though, and for the same reason: this is an intended refusal whose text
    the caller must see unchanged (see `mask_error` in mcp_server.py).

    Same flip side as well - this text reaches the AI client UNMASKED, so it
    is one fixed CONSTANT (`_PSEUDONYM_AS_INPUT`) without a single
    interpolation. Not "no names by careful phrasing" but no names BY
    CONSTRUCTION: a constant cannot carry a name, a path or table content.
    """


# The one message of `PseudonymAsInput`. A constant, never an f-string: see
# the class docstring for why nothing here may be interpolated. Product
# text - Dutch, plain, and without any advice to repair or set aside a file,
# because there is nothing wrong with it.
_PSEUDONYM_AS_INPUT = (
    "de naam in deze vraag heeft de vorm die deze server in de stand 'beperkt' voor "
    "pseudoniemen gebruikt; vermoedelijk is de vraag gesteld met een pseudoniem uit "
    "een eerder antwoord. In deze stand staan de echte namen niet in de antwoorden, "
    "en er kan ook niet op een pseudoniem doorgevraagd worden - stel de vraag met de "
    "echte naam van het certificaat. Er is niets kapot en er hoeft niets aan deze "
    "server gerepareerd te worden."
)


# How a name from the QUESTION is rendered when this export does not know
# it (see `_limit()`). Product text, and a fixed constant for the same
# reason as `_PSEUDONYM_AS_INPUT`: it can never carry a name by
# construction. Says explicitly that it came from the question, so the
# operator reading a report cannot mistake it for an object this appliance
# actually has - the honest reading of "we have no object by this name".
_UNKNOWN_NAME_IN_QUESTION = "(onbekende naam uit de vraag)"


_OBJECT_NUMBER = re.compile(r"^object-(\d+)$")

# Concurrency, layer one of two: the three question tools can concurrently
# read-enrich-write the same pseudonym table (fastmcp may run synchronous
# tool calls on separate worker threads). Without a lock, the second writer
# could overwrite the first writer's new assignment, or - worse - give the
# same new name a DIFFERENT pseudonym than the other thread just returned to
# its caller. A module-level `threading.Lock` covers the full
# read-modify-write as one atomic step WITHIN this process.
#
# Layer two: "no cross-process writers" is NOT a safe assumption - two
# server processes on the same pseudonym table produce a lost update (both
# read the same old state, the last write wins in its entirety, one of the
# two names vanishes without a trace). `threading.Lock` protects against
# nothing in ANOTHER process - which is exactly why `_ProcessLock` below
# stands NEXT to it, not instead of it: the thread lock serializes within
# this process first (and thereby also prevents two threads of the same
# process independently opening a handle on the lock file - Windows record
# locks are not guaranteed thread-safe within a single process), and only
# the thread holding the thread lock takes the cross-process file lock.
_TABLE_LOCK = threading.Lock()

# How many seconds `_ProcessLock.__enter__` waits for the file lock at most
# before giving up fail-closed (another process that never releases the lock
# must never leave this call hanging indefinitely).
_PROCESS_LOCK_TIMEOUT_S = 30.0
_PROCESS_LOCK_POLL_S = 0.05


class _ProcessLock:
    """Cross-process file lock around the full read-modify-write of the
    pseudonym table (see the comment at `_TABLE_LOCK` above for the proven
    lost-update scenario).

    Platform choice, documented explicitly: `msvcrt.locking` on a sidecar
    `.lock` file next to the pseudonym table itself. This product runs on
    Windows only (see start.py/README - no `fcntl`, which does not exist
    there); an OS-enforced file lock is, within that target platform, the
    portable-enough route, not an assumption about cooperative behavior
    between processes. `LK_NBLCK` (non-blocking) in a short poll loop gives
    an honest, time-bounded refusal (`TimeoutError`) instead of a call that
    can silently hang forever when another process never releases the lock.
    """

    def __init__(self, path: Path) -> None:
        self._lock_path = path.with_name(path.name + ".lock")
        self._handle = None

    def __enter__(self) -> _ProcessLock:
        try:
            self._lock_path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = open(self._lock_path, "a+b")
            if os.fstat(self._handle.fileno()).st_size == 0:
                # msvcrt.locking requires a byte to lock; a freshly created lock
                # file is 0 bytes. The content itself carries no meaning - this
                # file is never the pseudonym table itself.
                self._handle.write(b"0")
                self._handle.flush()
        except OSError as err:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            raise PseudonymTableLocked(
                f"het slot naast de vertaaltabel ({self._lock_path}) kon niet geopend worden"
                f" ({err.__class__.__name__}); staat daar een map of ontbreekt het schrijfrecht? Herstel dat"
                " en stel de vraag opnieuw"
            ) from err
        deadline = time.monotonic() + _PROCESS_LOCK_TIMEOUT_S
        while True:
            try:
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
                return self
            except OSError as err:
                if time.monotonic() >= deadline:
                    self._handle.close()
                    raise PseudonymTableLocked(
                        f"kon het cross-process slot op {self._lock_path} niet verkrijgen binnen "
                        f"{_PROCESS_LOCK_TIMEOUT_S}s - een ander proces houdt de vertaaltabel vast"
                    ) from err
                time.sleep(_PROCESS_LOCK_POLL_S)

    def __exit__(self, *exc_info) -> None:
        try:
            self._handle.seek(0)
            msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._handle.close()


def _next_number(existing: dict[str, str]) -> int:
    """The next pseudonym number, derived from the HIGHEST existing
    object-NN - not from `len(existing)`.

    `len()` assumes the table is a closed, gapless sequence. An operator who
    edits the table by hand - removing a row because an object no longer
    exists, for instance - breaks that assumption: with three remaining rows
    `len()` would hand out "4" again, even when the removed object once
    carried "object-04" and a higher number has thus already been issued. A
    NEW name would then reuse the pseudonym of an object the operator still
    knows from earlier reporting for an entirely DIFFERENT object - silent
    pseudonym reuse, exactly what this field must prevent. `max()+1` knows
    no such gap: every new number lies beyond every number this table has
    ever issued, regardless of how many rows remain today. Keys that do not
    follow the `object-NN` pattern (an operator may have entered a custom
    label) do not count and do not break the numbering.

    Since the storage direction is pseudonym -> real name, the pseudonym is
    the KEY, not the value - so this function scans `existing.keys()`.
    """
    highest = 0
    for key in existing.keys():
        # fullmatch, not match: a `$` anchor without MULTILINE may match
        # just before a trailing newline; fullmatch demands that the WHOLE
        # string satisfies the pattern.
        match = _OBJECT_NUMBER.fullmatch(str(key))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _collides_with_real_names(candidate: str, real_names: set[str]) -> bool:
    """A pseudonym candidate collides with the namespace of real names when
    it IS one (identity - the replacement then becomes a no-op and the real
    name leaks verbatim) OR has a substring relation with one of them - in
    EITHER direction. Testing equality alone is not enough: a candidate that
    happens to be a FRAGMENT of another real name (or the other way around,
    a real name carrying the candidate pseudonym as a fragment) makes the
    pseudonym table itself misleading, even when nothing visibly leaks in
    the rendered text itself.

    This is the ONE shared collision predicate for both the GENERATOR
    (`_next_free_pseudonym` below, called from `_load_table()` with
    `known_real_names = set(existing.values()) | set(names)` - a collection
    that includes the name THIS iteration is assigning right now) and the
    VALIDATOR (`_validate_loaded_table`). Both call it with an equally
    complete name collection - no row may exclude its own value from the
    test (see the validator's docstring for the leak that asymmetry
    caused)."""
    return any(candidate == name or candidate in name or name in candidate for name in real_names)


# Hard upper bound on `_next_free_pseudonym()`'s search (MEASURED -
# see `PseudonymSpaceExhausted` for the full
# mechanism). Generous on purpose: a real environment legitimately assigning
# this many pseudonyms in one table is not a case this bound should ever
# touch - it exists to turn a search that can structurally never succeed
# (a real name colliding with the fixed "object-" prefix itself) into a
# raised, honest refusal instead of a hang, not to police ordinary growth.
_MAX_PSEUDONYM_ATTEMPTS = 10_000


def _next_free_pseudonym(start: int, real_names: set[str]) -> tuple[int, str]:
    """The next pseudonym number FROM `start` whose candidate pseudonym is
    demonstrably disjoint from `real_names` (`_collides_with_real_names`).
    Reserves the namespace by CONSTRUCTION - generate, and skip on a
    collision - instead of trusting the assumption that "object-NN" will
    happen never to be a real name.

    BOUNDED (MEASURED): a real name that collides
    with the fixed "object-" prefix itself collides with EVERY candidate
    this loop could ever produce - the number changes, the colliding prefix
    does not, so the old `while True` never returned for such a name (see
    `PseudonymSpaceExhausted` for the full measurement). Fails closed
    instead, after `_MAX_PSEUDONYM_ATTEMPTS` tries: a raised error, never a
    hang. This is the OWNER of the bound - the one and only place this
    search happens - not a check duplicated at each caller."""
    for number in range(start, start + _MAX_PSEUDONYM_ATTEMPTS):
        candidate = f"object-{number:02d}"
        if not _collides_with_real_names(candidate, real_names):
            return number, candidate
    raise PseudonymSpaceExhausted(
        f"geen vrij pseudoniem gevonden binnen {_MAX_PSEUDONYM_ATTEMPTS} pogingen; "
        "een van de bekende namen botst blijkbaar met de vaste vorm 'object-NN' zelf - "
        "herzie de betrokken naam of stel de vraag zonder die naam opnieuw"
    )


def _entry_ref(*positions: int) -> str:
    """The ONE formatting helper for references to table entries in
    PseudonymTableBroken messages. Points at entries by POSITION (1-based,
    file order), never at the content of the entry itself - the message
    reaches the AI client unmasked (see the PseudonymTableBroken docstring),
    and a suspicious key or value is often precisely a real name. A shared
    helper instead of loose f-strings per raise site, so the sites cannot
    drift apart (same principle as validator and generator sharing the one
    collision predicate `_collides_with_real_names`)."""
    if len(positions) == 1:
        return f"vermelding {positions[0]}"
    return "vermeldingen " + " en ".join(str(p) for p in positions)


def _validate_loaded_table(raw: dict, path: Path, current_names: set[str]) -> dict[str, str]:
    """Semantic validation of a LOADED table: a file can be syntactically
    valid JSON and still be semantically broken - an identity table such as
    `{"ZEER_GEHEIM_VSERVER": "ZEER_GEHEIM_VSERVER"}` would let the real name
    through unfiltered in question/subject/outcome/evidence. Every deviation
    below raises the same `PseudonymTableBroken` as a broken JSON parse
    (fail-closed: NEVER a silent self-repair or overwrite; `_load_table()`
    writes only after a successful validation).

    The storage direction follows the design (par. 3): the file carries
    PSEUDONYM -> REAL NAME. The key must therefore follow the expected
    pseudonym pattern `object-NN`; a file in the OLD direction (real name as
    key) rightly fails on that pattern.

    Checked, in this order:
    - every key/value is non-empty text;
    - every key follows the pseudonym pattern `object-NN`;
    - no identity mapping (key == value);
    - no two pseudonyms point at the same real name (unique mapping);
    - no pseudonym collides (equality or substring, see
      `_collides_with_real_names`) with A REAL NAME from the full name
      collection (the table itself OR `current_names`) - INCLUDING its OWN
      assigned value. No row may exclude itself from this test: a table like
      `{"object-01": "object"}` is syntactically valid, yet the pseudonym
      carries its own full real name literally as a substring, so that name
      would stay readable in every rendered text.

    `current_names` carries only names this product knows STRUCTURALLY (from
    the export, and from the answer the engine built out of it). A name the
    CALLER supplied never reaches here - see `_collect_names()` and
    `render()` for why that separation exists and what it prevented.

    No refusal below cites the key or value of an entry - the message
    reaches the AI client unmasked, and a suspicious entry is often
    precisely a real name. Every message instead carries the position
    (`_entry_ref()`, 1-based in file order) and the reason category; with
    those the operator, who has the file itself in front of them, can find
    the row without the model ever seeing the content.
    """
    if not raw:
        return {}
    positions_per_name: dict[str, list[int]] = {}
    for position, (key, value) in enumerate(raw.items(), start=1):
        if not isinstance(key, str) or not key.strip():
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} bevat op {_entry_ref(position)} een ongeldige "
                "pseudoniemsleutel (leeg of geen tekst); dit bestand is de enige sleutel naar de "
                "echte namen en wordt daarom nooit overschreven - herstel het bestand of zet het "
                "aan de kant en stel de vraag opnieuw"
            )
        if not isinstance(value, str) or not value.strip():
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} draagt op {_entry_ref(position)} geen bruikbare echte "
                "naam (leeg of geen tekst); dit bestand is de enige sleutel naar de echte namen en "
                "wordt daarom nooit overschreven - herstel het bestand of zet het aan de kant en "
                "stel de vraag opnieuw"
            )
        if not value.isprintable():
            # 1.0.2: measured in the review, a value with a line break
            # ("x\n- forged line [vastgesteld]") was accepted. No real object
            # name carries a control or separator character.
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} draagt op {_entry_ref(position)} een echte naam met een "
                "stuurteken of regeleinde; dit bestand wordt daarom nooit overschreven - herstel het "
                "bestand of zet het aan de kant en stel de vraag opnieuw"
            )
        # fullmatch, not match+`$` - otherwise a key with a trailing newline
        # (e.g. "object-01\n") slips through the pattern test.
        if not _OBJECT_NUMBER.fullmatch(key):
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} heeft op {_entry_ref(position)} een sleutel die niet "
                "het verwachte pseudoniempatroon 'object-NN' volgt (mogelijk de OMGEKEERDE "
                "richting: dit bestand draagt sinds deze reparatie pseudoniem -> echte naam, niet "
                "andersom); dit bestand wordt daarom nooit overschreven - herstel het bestand of "
                "zet het aan de kant en stel de vraag opnieuw"
            )
        if key == value:
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} heeft op {_entry_ref(position)} een "
                "identiteitsafbeelding: het pseudoniem wijst naar een gelijknamige 'echte naam' - "
                "dat zou de echte naam ongefilterd doorlaten; dit bestand wordt daarom nooit "
                "overschreven - herstel het bestand of zet het aan de kant en stel de vraag opnieuw"
            )
        positions_per_name.setdefault(value, []).append(position)
    duplicate_groups = [p for p in positions_per_name.values() if len(p) > 1]
    if duplicate_groups:
        reference = "; ".join(_entry_ref(*group) for group in duplicate_groups)
        raise PseudonymTableBroken(
            f"de vertaaltabel op {path} wijst meerdere pseudoniemen toe aan dezelfde echte naam "
            f"({reference}); dit bestand wordt daarom nooit overschreven - herstel het bestand "
            "of zet het aan de kant en stel de vraag opnieuw"
        )
    # Tested against the FULL name collection, without excluding the row's
    # own value - otherwise a pseudonym that carries its OWN real name as a
    # substring (such as "object-01" -> "object") is no longer seen as a
    # collision.
    all_real_names = set(positions_per_name) | set(current_names)
    for position, key in enumerate(raw, start=1):
        if _collides_with_real_names(key, all_real_names):
            raise PseudonymTableBroken(
                f"de vertaaltabel op {path} heeft op {_entry_ref(position)} een pseudoniem dat "
                "botst (gelijk aan, of een substring-relatie met) een echte naam in de huidige "
                "naamverzameling - waaronder mogelijk zijn EIGEN toegewezen waarde; dit bestand "
                "wordt daarom nooit overschreven - herstel het bestand of zet het aan de kant en "
                "stel de vraag opnieuw"
            )
    return {str(k): str(v) for k, v in raw.items()}


def _atomic_write(path: Path, table: dict[str, str]) -> None:
    """Write to a temp file on the SAME volume (the same directory as
    `path`, so no cross-volume-rename pitfall), flush + fsync before the
    rename, then replace with `os.replace` - atomic on both Windows and
    POSIX. A reader opening the file at this very moment (an operator
    inspecting it by hand, for instance) therefore always sees EITHER the
    old, OR the fully new content - never a half-written in-between state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(table, indent=2, ensure_ascii=False)
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    with open(temporary, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def _load_table(path: Path, names: list[str]) -> dict[str, str]:
    """Loads/enriches the pseudonym table. Existing assignments NEVER change
    (stability across calls); new names get the next number AFTER the
    highest existing one (see `_next_number`) that is demonstrably disjoint
    from all known real names (`_next_free_pseudonym`).

    This file carries PSEUDONYM -> REAL NAME (the design, par. 3). A loaded
    table is first validated semantically (`_validate_loaded_table`): every
    deviation (identity, duplicate assignment, wrong pattern, namespace
    collision, empty/non-text values) fails closed BEFORE anything is
    written.

    `names` carries ONLY structurally known names (see `_collect_names()`):
    a name the caller invented never reaches this function, so it can
    neither accuse a healthy table nor add a row of its own.

    A BROKEN table (unreadable as a file, no valid JSON, no JSON object) is
    never silently replaced by a fresh one. This file is, for the operator,
    the ONLY decode key to the real object names (see README, "The
    disclosure switch"). `PseudonymTableBroken` names the path and asks the
    operator to repair the file or set it aside; `render()` (and thus the
    answer) then fails visibly instead of handing out pseudonyms that no
    longer match the old table - or instead of using a semantically broken
    table as if it were healthy.

    Concurrency, two layers (see the comment at `_TABLE_LOCK` above):
    `_TABLE_LOCK` serializes threads WITHIN this process, `_ProcessLock`
    serializes processes on the same table file. The full
    read-validate-enrich-write sequence sits under BOTH.
    """
    with _TABLE_LOCK:
        with _ProcessLock(path):
            existing: dict[str, str] = {}
            if path.exists():
                try:
                    raw_text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    # UnicodeDecodeError alongside OSError, as everywhere else
                    # in the codebase (target.py, start.py): an unreadable
                    # TEXT ENCODING is just as much a read failure as an
                    # unreadable FILE. Only the class name, never str(exc) -
                    # a UnicodeDecodeError message quotes the offending
                    # bytes, and even one byte is table content.
                    raise PseudonymTableBroken(
                        f"de vertaaltabel op {path} kon niet gelezen worden ({exc.__class__.__name__}); "
                        "dit bestand is de enige sleutel naar de echte namen en wordt daarom nooit "
                        "overschreven - herstel het bestand of zet het aan de kant en stel de vraag opnieuw"
                    ) from exc
                try:
                    raw = json.loads(raw_text)
                except (RecursionError, MemoryError):
                    # 1.0.2: too deep for the parser is a broken table too.
                    raise PseudonymTableBroken(
                        f"de vertaaltabel op {path} is te diep genest om te lezen; dit bestand is de enige"
                        " sleutel naar de echte namen en wordt daarom nooit overschreven - herstel het bestand"
                        " of zet het aan de kant en stel de vraag opnieuw"
                    ) from None
                except json.JSONDecodeError as exc:
                    # Only line/column, not str(exc) - some JSONDecodeError
                    # messages quote a loose character from the file
                    # ("Invalid control character '\x00' at ..."), and even
                    # a single character is table content.
                    raise PseudonymTableBroken(
                        f"de vertaaltabel op {path} is niet leesbaar als JSON "
                        f"(parsefout op regel {exc.lineno}, kolom {exc.colno}); "
                        "dit bestand is de enige sleutel naar de echte namen en wordt daarom nooit "
                        "overschreven - herstel het bestand of zet het aan de kant en stel de vraag opnieuw"
                    ) from exc
                if not isinstance(raw, dict):
                    raise PseudonymTableBroken(
                        f"de vertaaltabel op {path} draagt geen JSON-object op het topniveau; "
                        "dit bestand is de enige sleutel naar de echte namen en wordt daarom nooit "
                        "overschreven - herstel het bestand of zet het aan de kant en stel de vraag opnieuw"
                    )
                existing = _validate_loaded_table(raw, path, set(names))

            known_real_names = set(existing.values()) | set(names)
            pseudonym_of_name = {v: k for k, v in existing.items()}
            next_number = _next_number(existing)
            for name in sorted(names):  # assignment in a fixed order
                if name not in pseudonym_of_name:
                    next_number, candidate = _next_free_pseudonym(next_number, known_real_names)
                    existing[candidate] = name
                    pseudonym_of_name[name] = candidate
                    # Generated aliases are not real names. Treating them as
                    # such makes object-10 block object-100 and exhausts every
                    # later candidate once this call has assigned 99 aliases.
                    # Monotonic numbering already guarantees unique keys.
                    next_number += 1
            _atomic_write(path, existing)
            return existing


def resolve_pseudonym(value: str, names: tuple[str, ...], path: Path) -> str | None:
    """The real name behind a pseudonym, or None when there is none.

    The INVERSE of what `render()` does, and it exists for exactly one
    caller: the writing path. At `openheid: beperkt` a caller only ever saw
    pseudonyms, so that is what it hands back - and `validate()` judges real
    object names.

    Three cases, and the order matters. A value that is already a real name
    (it is in `names`) is returned unchanged: the seam never invented that
    name, so the caller may have it from the operator. A value with the
    pseudonym SHAPE is looked up in the table and returns None when it is not
    in there - the same refusal for an issued and an unissued pseudonym, so
    the difference cannot be walked (see `render`). Anything else is not a
    name this product knows, and that is None as well.
    """
    if value in names:
        return value
    if not has_pseudonym_shape(value):
        return None
    return _load_table(path, list(names)).get(value)


def has_pseudonym_shape(value: str) -> bool:
    """Does this value carry the SHAPE of a pseudonym this seam hands out?

    The same test `render()` makes on a caller-supplied name, named once so
    the writing path can make it too instead of copying the pattern. It asks
    about the SHAPE and never about the table - see `render()` for why that
    difference matters, and `resolve_pseudonym()` above for the other caller.

    The writing path needs it for the one decision `render()` cannot make for
    it: a refused value that is NOT pseudonym-shaped is a name the caller
    invented, and it must reach `render()` as `caller_name` so the seam
    replaces it with its fixed text instead of echoing it. A value that IS
    pseudonym-shaped must NOT, because for that one `render()` refuses with
    `PseudonymAsInput` - and it does so only for an UNISSUED pseudonym, which
    is exactly the difference this refusal exists to hide.
    """
    return _OBJECT_NUMBER.fullmatch(value) is not None


def _replacement_pattern(names: list[str], word_bounded: frozenset[str] = frozenset()) -> re.Pattern[str] | None:
    """ONE alternation of all real names (already sorted descending by
    length by the caller - the masking lesson: a shorter name sitting inside
    a longer one must never break the longer match), so that the whole
    replacement happens in ONE single `re.sub()` pass.

    A sequential `for name in names: text = text.replace(...)` loop is
    structurally vulnerable to exactly this class of bugs: the OUTPUT of an
    earlier replacement (a just-inserted pseudonym) can be seen as input
    again by a LATER name in the same loop. A single regex pass scans only
    the ORIGINAL text; every match position is replaced exactly once via the
    callback in `_replace()`, so an inserted pseudonym can never be hit a
    second time.

    `word_bounded` names get `(?<!\\w)...(?!\\w)` lookarounds around their
    own branch of the alternation - MEASURED:
    the caller-supplied name (`_limit()`'s `invented_name`) used to join
    this alternation bare, with no minimum length and no word boundary, so
    a one-character value like "e" matched every bare 'e' anywhere in the
    text - shredding ordinary Dutch words ("certificaat_klaarzetten",
    "gewijzigd") into a dozen forged placeholder fragments. `\\w` includes
    the underscore, so a name that sits INSIDE a longer identifier never
    has a boundary there and stays untouched; a name that stands on its
    own - bounded by whitespace, punctuation or the string's edges - still
    matches and is still masked.

    MEASURED SECOND: the first repair used
    `\\b...\\b`, and `\\b` demands an actual WORD character on the side it
    tests - it matches only at a transition between a `\\w` and a
    non-`\\w` position. A name that itself STARTS or ENDS on a non-word
    character never gets that transition at the string's edge or after a
    plain space, so it was never masked there - and a WILDCARD CERTIFICATE
    NAME (`*.gjk.nl`, starting with `*`), a name with a trailing dot
    (`gjk.nl.`) and a name starting with a hyphen (`-lab`) all reproduced
    that leak, unmasked and verbatim, in exactly the ordinary shapes a
    NetScaler certnaam or object name takes. `(?<!\\w)`/`(?!\\w)` ask a
    different, correct question: not "is there a word character here AND a
    transition", but "is there NOT a word character here" - true at a
    plain space or the string's edge regardless of what the matched text
    itself starts or ends with, while staying exactly as strict as `\\b`
    INSIDE an ordinary word (a name embedded on both sides by word
    characters, such as "lab" inside "instalabelwissel", still fails both
    checks and stays unmasked - the item-9 guarantee is unchanged).

    MEASURED THIRD: applying `(?<!\\w)` and
    `(?!\\w)` UNCONDITIONALLY on both sides - the fix described just above
    - is not a superset of `\\b...\\b` either, in the OTHER direction. At
    a `\\b` transition, exactly one side of the match has a word
    character; an unconditional lookaround forbids a word character on
    THAT side too, regardless of what the matched name itself starts or
    ends with, and so fails where `\\b` succeeded. Measured: `*.gjk.nl`
    right after "ssl_" (the `_` blocks `(?<!\\w)`), `-lab` right after
    "gjk" (the `k` blocks `(?<!\\w)`), and `gjk.nl.` right before "crt"
    (the `c` blocks `(?!\\w)`) - all three MASKED CORRECTLY by the
    original `\\b...\\b`, all three left LITERAL by the unconditional
    lookaround pair - the exact opposite class of leak from the one that
    pair was written to close.

    Fix: apply each lookaround PER SIDE, according to the name's OWN edge
    character - `(?<!\\w)` only when the name starts with a word
    character, `(?!\\w)` only when it ends with one. A side where the name
    itself has no word character carries no guard at all, so nothing on
    that side can ever block the match.

    This per-side rule is PROVABLY a strict superset of `\\b...\\b` (not
    merely measured to be, on the handful of forms above): take one edge
    at a time, comparing the boundary position between the character
    outside the match ("outer") and the name's own first/last character
    ("edge"). `\\b` there is true exactly when `is_word(outer) !=
    is_word(edge)`. When `edge` IS a word character, that reduces to `NOT
    is_word(outer)` - precisely `(?<!\\w)`'s own condition, so the
    per-side rule (which applies the guard on exactly this side) is
    IDENTICAL to `\\b` there. When `edge` is NOT a word character, `\\b`'s
    condition reduces to `is_word(outer)` - sometimes true, sometimes
    false - while the per-side rule applies no guard on this side at all
    and is always true. So per side, the per-side rule's truth value is
    never LOWER than `\\b`'s, only ever equal or higher. The two sides
    combine with AND, and an implication that holds on each side
    independently also holds on their conjunction: whatever `\\b...\\b`
    matched, the per-side guard matches too, and it also matches
    everything measured above that `\\b...\\b` matched but the
    unconditional pair did not.

    PUNCTUATION-ONLY names get NO pattern at all, not even an unguarded
    literal: a caller-supplied value with no
    word character anywhere in it is not an object name -
    `handelen._NAME` (`[A-Za-z][A-Za-z0-9._-]{0,62}`) requires a NetScaler
    object name to START with a letter, so a string of pure punctuation
    cannot identify an appliance object. There is nothing to protect
    there, and an unguarded literal would instead forge a placeholder
    between any two ordinary non-word characters in ordinary product text
    (a plain hyphen sitting between two spaces, for instance - the item-9
    shredding class, reopened by the unconditional-both-sides pair for
    exactly this shape of name). The same absence-of-a-word-character
    reasoning covers a whitespace-only name. Both are filtered out by the
    caller of this function before a name ever reaches `word_bounded` -
    see `render()`.

    Kept to ONE combined pass rather than a second `re.sub()` afterwards: a
    second pass over the fixed placeholder text this one may have just
    inserted would reopen exactly the re-matching hazard this function's
    single-pass design exists to close, this time against the placeholder
    text itself.

    Which direction this guard errs, stated accurately this time - an
    earlier version of this docstring (and this round's own report) made
    this same claim about the UNCONDITIONAL both-sides lookaround pair and
    got it wrong: that pair is NOT one-directional relative to `\\b...\\b`,
    as the MEASURED THIRD paragraph above demonstrates with three real
    leaks it reopened. The PER-SIDE rule actually shipped here is the one
    guard of the three tried on this branch (`\\b...\\b`, the unconditional
    pair, and this one) that is provably one-directional: relative to
    `\\b...\\b` it only ever WIDENS which values get masked, on the
    per-edge proof above, and never narrows. In doubt a name is still
    masked rather than emitted, and that direction is now backed by a
    proof rather than an assumption - but it is a property of THIS
    construction, not a law that any future edit to this function keeps
    for free."""
    if not names:
        return None
    pieces = []
    for n in names:
        if n in word_bounded:
            left = r"(?<!\w)" if re.match(r"\w", n[0]) else ""
            right = r"(?!\w)" if re.match(r"\w", n[-1]) else ""
            pieces.append(f"{left}{re.escape(n)}{right}")
        else:
            pieces.append(re.escape(n))
    return re.compile("|".join(pieces))


def _replace(text: str, pattern: re.Pattern[str] | None, name_to_pseudonym: dict[str, str]) -> str:
    if pattern is None:
        return text
    return pattern.sub(lambda m: name_to_pseudonym[m.group(0)], text)


def _limit(
    answer: Answer,
    extra_names: tuple[str, ...],
    path: Path,
    invented_name: str | None = None,
) -> Answer:
    """Replaces EVERY text field the answer carries, not only the fields
    ASSUMED to be able to carry object names. `question`/`subject`/
    `outcome`/`evidence`/`reason`, and just as much `ReadGap.source` AND
    `ReadGap.reason` (both), and `NotAssessed.subject`/`.reason`. A resource
    path such as "config/sslvserver" contains none of the collected names,
    so the replacement is a no-op there and thus harmless - but for a
    `ReadGap.source` from impact.py ("...vservername=LB_VS_PORTAAL") or
    action.py (which puts a vserver-name subject straight into the source),
    that same replacement is exactly what keeps the fail-closed paths from
    leaking.

    `invented_name` (see `_collect_names()`) gets no pseudonym and no table
    row, but it does NOT stay in the text: it is replaced by the fixed
    `_UNKNOWN_NAME_IN_QUESTION`. See the comment at that replacement for why
    echoing it verbatim was a real leak rather than a harmless echo.

    What that does NOT close, stated here so no one has to rediscover it: a
    caller can still tell from an answer WHETHER this export knows a name -
    a known name comes back as a pseudonym, an unknown one as the fixed
    text. Every answering behavior has that difference (refusing unknown
    names only moves the signal from the placeholder to the refusal), and
    the one variant that truly hides it is the old one: minting a fresh
    pseudonym for every invented name - at the price of letting any client
    grow the operator's table without bound. Which side that trade falls on
    is a product decision, not one this seam makes on its own.
    """
    names = _collect_names(answer, extra_names, invented_name)
    # `_load_table()` returns PSEUDONYM -> REAL NAME (the design, par. 3); the
    # replacement itself needs the opposite direction (real name ->
    # pseudonym), built locally and never written back.
    pseudonym_to_name = _load_table(path, names) if names else {}
    name_to_pseudonym = {v: k for k, v in pseudonym_to_name.items()}
    to_replace = list(names)
    if invented_name:
        # The invented name gets NO pseudonym and no table row (see
        # `_collect_names()`), but it must still leave the text - it is
        # replaced by one FIXED text instead. A deliberate assignment, not
        # an omission: leaving it in verbatim would let a real name reach
        # the answer whenever this export happens not to know it (a read
        # gap on the name source, or simply a certificate uploaded after
        # the last scan - the operator asking about what they just
        # installed is the normal case, not an edge case). That would break
        # the one promise this setting makes: the server never emits a real
        # object name.
        #
        # Deliberately OVERWRITES any mapping this name may already have
        # from the table (a name from an EARLIER export, no longer present
        # in this one). Otherwise the rendering would depend on table
        # membership, and that difference would itself say whether this
        # environment ever knew the name. One rule instead: does the CURRENT
        # export know it - pseudonym; does it not - this fixed text.
        name_to_pseudonym[invented_name] = _UNKNOWN_NAME_IN_QUESTION
        to_replace.append(invented_name)
    if not to_replace:
        # An empty collection can practically only arise from an EMPTY
        # export (no certkey objects, no bindings) AND an answer without
        # findings of its own AND no name from the question. Then there is
        # nothing to replace either: the unchanged text cannot carry an
        # object name the engine never knew (see the fail-closed reasoning
        # in `names_from_export()`), so this bypass is safe rather than a
        # hole.
        return answer
    # Descending by length again, now including the invented name - the
    # masking lesson holds just as much for it: a short name from the
    # question sitting inside a longer real name must not break the longer
    # match.
    to_replace.sort(key=len, reverse=True)
    word_bounded = frozenset({invented_name}) if invented_name else frozenset()
    pattern = _replacement_pattern(to_replace, word_bounded)

    def s(text: str) -> str:
        return _replace(text, pattern, name_to_pseudonym)

    return _map_text(answer, s)


def _map_text(answer: Answer, s) -> Answer:
    """`answer` with `s` applied to EVERY text field it carries - the one
    list of fields both the masking (`_limit`) and the name cut
    (`_cut_long_names`) walk, so neither can forget one the other knows."""
    copy = replace(
        answer,
        question=s(answer.question),
        findings=[
            replace(b, subject=s(b.subject), outcome=s(b.outcome), evidence=s(b.evidence), reason=s(b.reason))
            for b in answer.findings
        ],
        read_gaps=[replace(g, source=s(g.source), reason=s(g.reason)) for g in answer.read_gaps],
        not_assessed=[replace(n, subject=s(n.subject), reason=s(n.reason)) for n in answer.not_assessed],
        # The closing "doel: ..." line (`Answer.to_text()`) is built from
        # `data_target`, which `stamp_data()` sets to the export's own
        # target name - a name this seam must mask exactly like every other
        # text field. `s()` only replaces what sits in the twelfth family
        # (`names_from_export`), so a `None` target or the boundary gate's
        # fixed `TARGET_NAME_REFUSED` phrase pass through unchanged.
        data_target=s(answer.data_target) if answer.data_target else answer.data_target,
    )
    if getattr(answer, "affected_vservers", None):
        copy = replace(copy, affected_vservers=tuple(s(n) for n in answer.affected_vservers))
    if getattr(answer, "issued_certificates", None):
        copy = replace(copy, issued_certificates=tuple(s(n) for n in answer.issued_certificates))
    if getattr(answer, "affected_services", None):
        copy = replace(copy, affected_services=tuple(s(n) for n in answer.affected_services))
    if getattr(answer, "other_uses", None):
        copy = replace(
            copy,
            other_uses=tuple(
                replace(u, certkey=s(u.certkey), owner=s(u.owner), evidence=s(u.evidence), reason=s(u.reason))
                for u in answer.other_uses
            ),
        )
    return copy


def _cut_long_names(answer: Answer, names: tuple[str, ...], caller_name: str | None) -> Answer:
    """1.0.2: every known object name (`extra_names`, the structural
    collection) and the caller's own name longer than `NAME_ECHO_MAX_LEN`
    is cut to that length with `NAME_CUT_NOTE`, in every text field, in
    one pass (longest first, as the masking does). Measured before: the
    limit held only for `status_namen` and for a name as a subject, and a
    certificate name of 5000 characters reached `rapport_dekking` whole.
    A name of at most 128 characters is untouched."""
    candidates = [*names, *([caller_name] if caller_name else [])]
    long_names = sorted(
        {name for name in candidates if isinstance(name, str) and len(name) > NAME_ECHO_MAX_LEN},
        key=len,
        reverse=True,
    )
    if not long_names:
        return answer
    pattern = re.compile("|".join(re.escape(name) for name in long_names))

    def s(text: str) -> str:
        return pattern.sub(lambda match: match.group(0)[:NAME_ECHO_MAX_LEN] + NAME_CUT_NOTE, text)

    return _map_text(answer, s)


def _minimal(answer: Answer, tool: str) -> str:
    """Aggregates only. The stamp lines (knowledge/data/target) come from
    `Answer.stamp_lines()`, the one builder `to_text()` reads too, so this
    rendering cannot drift from the canonical closing lines. That is safer
    than the mechanism it replaced - rendering an artificially EMPTIED copy
    of the answer and slicing its text - because such a copy inherits
    whatever `to_text()` says about an EMPTY answer, and this answer is not
    empty: measured, the empty-answer sentence landed under "1 bevinding(en)"
    and "1 leesgat(en)" here.

    An ALREADY EXPIRED certificate is the worst fact this answer can carry -
    an `if days: ... elif already_expired: ...` ordering would silently DROP
    the expired certificate as soon as even ONE other certificate with
    remaining days sat in the same findings list (`days` would be non-empty,
    so the `elif` would never be reached). An operator reading only this
    line would then hear "kortste resterende looptijd: 200 dagen" while
    something had already expired - an under-reported worst fact is just as
    dangerous here as a missed fact. "Er is al iets verlopen" is therefore
    reported FIRST and ALWAYS whenever it applies, with the shortest
    remaining term of the REST alongside when there is one - never hidden
    behind a milder conclusion.

    The action line is TYPED, never counted and never derived from free
    text. Deriving "action needed" from `len(answer.findings)` is a count,
    not a typing, and it produces false verdicts in BOTH directions:
    - with a read gap open, a missing finding may be hidden behind the
      failed read (false "no"), and the read gap can just as well be the
      ONLY reason a NOT_ESTABLISHED finding exists at all (false "yes" -
      action.py deliberately ADDS a finding on a read gap: "geen
      wijzigingsvoorstel zolang de impact niet vaststaat");
    - without read gaps, a NOT_ESTABLISHED finding (the ca flag missing on
      a binding) counted as "there is a finding" -> "yes" while nothing is
      ESTABLISHED, and an ESTABLISHED finding whose OWN TEXT says "geen
      gebonden virtuele servers gevonden" (there is explicitly NOTHING)
      counted just as hard, purely because `len(findings) == 1`.
    The word "ja" therefore never follows "actie nodig:". A NOT_ESTABLISHED
    finding OR a read gap always yields the honest "niet vast te stellen uit
    dit antwoord". Only when ALL findings are ESTABLISHED, there are no read
    gaps AND there is at least one finding, does a DERIVED statement - never
    an assertion - appear: "mogelijk actie nodig: er zijn N vastgestelde
    bevinding(en)"; the reader draws the conclusion from the findings below
    it, this product does not do that for them. Only with zero findings AND
    zero read gaps AND zero NOT_ESTABLISHED is "actie nodig: nee" honest.
    `Certainty.ESTABLISHED`/`NOT_ESTABLISHED` is the only source of truth
    here - not `len(...)`, not the content of an outcome text.
    """
    # 1.0.2: from the typed fields of the finding, never from its
    # outcome text (that text carries object names).
    days = [b.days_left for b in answer.findings if b.days_left is not None and not b.expired]
    already_expired = any(b.expired for b in answer.findings)
    if already_expired:
        if days:
            severity = f"er is al iets verlopen; kortste resterende looptijd van de rest: {min(days)} dagen"
        else:
            severity = "er is al iets verlopen"
    elif days:
        severity = f"kortste resterende looptijd: {min(days)} dagen"
    else:
        severity = "resterende looptijd niet afleidbaar uit dit antwoord"
    not_established = any(b.certainty is not Certainty.ESTABLISHED for b in answer.findings)
    # A finding flagged `counted_at_minimal=False`
    # SUMMARIZES other findings already in `answer.findings` (compare.py's
    # three block-header lines) - counting it too would tally the same
    # fact twice. The boolean scans above (`already_expired`,
    # `not_established`) still read ALL findings: those ask "does this
    # exist anywhere", not "how many", and a NOT_ESTABLISHED summary
    # finding is still real evidence that something here is uncertain.
    countable = [b for b in answer.findings if b.counted_at_minimal]
    if answer.read_gaps or not_established:
        action_line = "actie nodig: niet vast te stellen uit dit antwoord"
    elif countable:
        action_line = f"mogelijk actie nodig: er zijn {len(countable)} vastgestelde bevinding(en)"
    else:
        action_line = "actie nodig: nee"
    lines = [
        f"Vraag: {tool} (stand: minimaal)",
        "",
        f"- {len(countable)} bevinding(en)",
        f"- {len(answer.read_gaps)} leesgat(en) (niet vastgesteld, geen stille aanname)",
        f"- {len(answer.not_assessed)} dimensie(s) bewust niet beoordeeld",
        f"- {severity}",
        f"- {action_line}",
    ]
    # The stamps come from the REAL answer, through the one method that builds
    # them. This used to render an artificially EMPTIED copy of the answer and
    # slice its text at a magic index to harvest the same two lines. That copy
    # was empty by construction, so every line `to_text()` gained landed here
    # too - including, measured, the empty-answer sentence, printed under
    # "1 bevinding(en)" and "1 leesgat(en)" in an answer that had both. The one
    # blank line below is the separator this product puts between a content
    # block and the stamps; it used to be the leading element of that slice.
    #
    # This rides along on that builder instead of replacing it: a
    # pseudonym for a single value (the one target this whole answer
    # describes) carries no information a reader could not already infer from
    # asking twice, so `minimaal` does not spend a pseudonym on it - it says
    # plainly that the target is not shown at this level. Only when a target
    # was actually RECORDED (`answer.data_target` truthy, whether a real name
    # or the boundary gate's `TARGET_NAME_REFUSED` phrase) does this apply;
    # `None` ("niet vastgelegd") is already the honest text and names nothing
    # to hide. `_safe` inside `stamp_lines` lets this fixed sentence through
    # unchanged (measured).
    target_override = _TARGET_NOT_SHOWN_AT_MINIMAL if answer.data_target else answer.data_target
    stamped = replace(answer, data_target=target_override)
    # The opening lines (`Answer._leading_lines()`: a `HealthAnswer` opens
    # with its data age) come from the SAME
    # stamped copy as the footer (`stamp_lines()`), so the two
    # renderings of the target cannot differ; a plain `Answer` contributes no
    # opening line and renders exactly as before.
    return "\n".join(stamped._leading_lines() + lines + [""] + stamped.stamp_lines())


def _without_full_only(answer: Answer) -> Answer:
    """Everything an answer may only say at 'volledig', removed BEFORE the
    limited/minimal rendering runs.

    Two things go, and both for the ONE reason in `Finding.only_in_full`: a
    statement about the caller's own search term is an adaptive substring
    oracle at every level where names are masked instead of shown.

    - the findings flagged `only_in_full` - so no candidate line, and no
      candidate COUNT either (the count is the same oracle; `_minimal()`
      counts what is left here, not what was built);
    - `ImpactAnswer.name_candidates`, the explicit collection those findings
      travel on. Not decoration: `_collect_names()` reads that field, so
      leaving it in would keep writing probe-derived names into the
      operator's pseudonym table - the very table this setting protects -
      for an answer that no longer shows them.

    Deliberately here and not in impact.py/dienst.py: THIS is the one place
    that knows the disclosure level, and a rule that lives at the seam cannot
    be forgotten by the next module that writes such a finding.
    """
    stripped = replace(answer, findings=[f for f in answer.findings if not f.only_in_full])
    if getattr(answer, "name_candidates", None) is not None:
        stripped = replace(stripped, name_candidates=None, certificate_count=0)
    return stripped


def render(
    answer: Answer,
    level: Disclosure,
    *,
    tool: str,
    extra_names: tuple[str, ...] = (),
    caller_name: str | None = None,
    pseudonym_table_path: Path | None = None,
) -> str:
    """The one point where an answer becomes text. Every level is computed.

    `extra_names`: object names the caller knows STRUCTURALLY - in practice
    the output of `names_from_export()`: every object name the export knows,
    regardless of whether it appears as a subject in this answer.

    `caller_name`: the name that came from the tool ARGUMENT (the certnaam).
    It is passed SEPARATELY from `extra_names` because its ORIGIN decides
    how it may be handled - and that question is settled here, at the seam,
    and nowhere else.

    A name the EXPORT knows is a real appliance object (it already sits in
    `extra_names` and is masked structurally) - even when it happens to be
    shaped like a pseudonym. Only a name `extra_names` does NOT contain is
    caller-invented, and for that one this function makes the single
    decision that follows from it:

    - does it carry the PSEUDONYM SHAPE, then the caller is asking on with a
      reference this setting cannot resolve: refuse honestly
      (`PseudonymAsInput`). Answering would mean reporting about the name
      itself, and "geen gebonden virtuele servers gevonden" reads exactly
      like an answer about the real object behind that pseudonym - a false
      green on the very question being asked;
    - otherwise it is simply a name this export does not know. It is then
      kept out of the name collection entirely (see `_collect_names()` for
      the measured defect that repairs) and appears in the text as one
      fixed placeholder, never as the caller typed it (see `_limit()`).

    That first test deliberately asks about the SHAPE and never whether the
    table actually holds this pseudonym. Two reasons, and neither is
    convenience. It keeps the refusal path away from the table entirely - no
    read, no lock, no file state - so this decision cannot be influenced by
    the file it is meant to protect. And it closes a probe that existed
    BEFORE this repair: an issued pseudonym used to be refused while an
    unissued one was answered, so a client could walk `object-01` upward and
    read off how many pseudonyms had been handed out. Now both give the same
    refusal, and that difference in behavior is gone.
    """
    if level is Disclosure.FULL:
        return _cut_long_names(answer, extra_names, caller_name).to_text()
    # Below 'volledig' first: what may only be said at 'volledig' leaves the
    # answer BEFORE any masking or counting sees it (see
    # `_without_full_only`).
    answer = _without_full_only(answer)
    if level is Disclosure.LIMITED:
        if pseudonym_table_path is None:
            raise ValueError("disclosure level 'beperkt' requires a pseudonym_table_path")
        # `caller_name` must carry at least one WORD character to become
        # `invented`. Covers two measured gaps at once: a whitespace-only value used to pass this check (it is
        # truthy) where `extra_names` already filters blank entries with
        # `.strip()` (see the collection above), and a punctuation-only
        # value (e.g. "-") is not an object name at all - `handelen._NAME`
        # requires a NetScaler object name to start with a letter, so pure
        # punctuation cannot identify an appliance object. Both used to
        # reach `_replacement_pattern()`'s `word_bounded` branch as a bare,
        # unguarded literal (neither edge has a word character, so neither
        # lookaround ever applied) and forge placeholders into ordinary
        # product text; see that function's docstring for the measured
        # example. Filtering here, before `_limit()`, keeps the fix in one
        # place instead of hardening the regex construction against a name
        # it should never have received.
        invented = (
            caller_name if caller_name and re.search(r"\w", caller_name) and caller_name not in extra_names else None
        )
        if invented is not None and _OBJECT_NUMBER.fullmatch(invented):
            raise PseudonymAsInput(_PSEUDONYM_AS_INPUT)
        return _limit(answer, extra_names, pseudonym_table_path, invented).to_text()
    return _minimal(_cut_long_names(answer, extra_names, caller_name), tool)
