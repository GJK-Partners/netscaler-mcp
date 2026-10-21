"""A TLS grade per virtual server, from the same ruleset as the healthcheck.

Mirrors backend/readonly/Invoke-NshcSslGrade.ps1 of NSHC 1.0.1: the same three
dimensions with the same weights, the same letter thresholds, the same HSTS cap
and the same certificate gate, all read from the vendored ruleset
`nshc-ssl-baseline` 2026.08 (rulesets.py) - never from a number in this file.

WHAT A LETTER MEANS HERE, said before anyone reads one: this is a
CONFIGURATION weighing, not a live SSL-Labs scan and not a pen test. What the
appliance offers in a real handshake - OCSP stapling in practice, the actual
chain order, an mTLS trust anchor in use - is not proven by this. Design 2.8
names that boundary; this module keeps to it.

TWO OUTCOMES THAT LOOK ALIKE AND ARE NOT (NSHC 0.96 made this distinction and
it must survive here):
- `T`: read succeeded and NO server certificate is bound. A finding, not a
  gap. Without a server certificate the vserver cannot complete a handshake.
  NSHC's own ruleset also lands an EXPIRED certificate on `T`
  (`certGate.expiredCapsTo`) - the same letter, a different reason, both
  established.
- `NIET BEOORDEELD`: a critical source could not be read. Never a letter, and
  in particular never an A.

THE HARD READ RULE: protocol comes from the SSL PROFILE as soon as one is
bound. A bound profile that is not in the read profile list gives NIET
BEOORDEELD - never the vserver's own value, because the profile overrides it
and we did not read it. The resolver is ssl_precedence.resolve(), shared with
hidden_rules.py, for the reason NSHC states itself: two implementations could
give two answers to one question inside one report. Still not modified for
this task; see below for why it did not need to be.

A dedicated review against NSHC and the real fixture measured 6
Critical and 6 Important defects here. Every one
below is that review's finding, not a fresh design choice; the
measurement behind each one, and the mutation that proves its fix, is
written out at the finding itself in the list below.

- Ciphers now come from the cipher GROUP bound to the PROFILE
  (`sslprofile_sslcipher_binding.by-parent.json` -> `cipheraliasname`,
  fallback `ciphername`/`ciphergroupname`, NSHC :193-232) as soon as a
  profile is bound and READ - never from the legacy per-vserver
  ciphersuite binding, even when one is present and would otherwise win by
  accident. The group is expanded through its own binding file
  (`sslcipher_binding.by-parent.json`) WHEN the export carries one;
  otherwise the raw group name stands in as the one (unexpanded) cipher
  entry - the SAME limitation the vserver path already accepted for a bare
  "DEFAULT" name, not a new one. Goes THROUGH `ssl_precedence.resolve()`'s
  profile_bound/profile_read state (not around it) - the "one resolver"
  rule; `resolve()`'s own VALUE is not used for this field, only its state.
- A certificate that could not be read (absent certkey object, or a
  non-integer `daystoexpiration`/`publickeysize`) now drops the vserver to
  NIET BEOORDEELD, evaluated BEFORE the missing/continue decision - NSHC's
  `sslcertkey` / `sslcertkey.daystoexpiration` / `sslcertkey.publickeysize`
  are critical reads (:305); this module silently graded "not expired, not
  weak" instead.
- An unreadable `config/sslvserver` now propagates its read gap into
  the "gradeverdeling" finding (NOT_ESTABLISHED, the gap's own reason) and
  the genuinely-empty case (read fine, zero vservers) has its OWN wording -
  the two used to share one ESTABLISHED sentence.
- A binding whose ONLY certificate is a CA binding (`ca` true) no
  longer counts as a server certificate - mirrors NSHC's
  Test-NshcIsServerCertBinding (:84-95). `snicert` is not filtered on.
- `_parents()` now tells "parent absent from the binding file" (a read
  gap) apart from "parent present, confirmed zero rows" (an EMPTY list,
  never a gap) - NSHC's own three-way distinction (:243-253). Unlocks
  letter `T` (`no-server-cert-bound`) and `default-cipher-group` on a real
  export; previously only reachable through a degenerate hostile export.
- An ECC certificate (signaturealg or publickey matching
  `(?i)ecdsa|ecpublickey`) is never flagged as a weak RSA key - mirrors
  NSHC's `isEcc` gate (definition :278, consumed in the weak-key gate :388).
- `hsts`/`ocsp`/hsts-max-age are now filled ONLY from a bound-and-read
  profile (NSHC :142,167-171,174-176) - with no profile bound they stay
  unset, same as NSHC (`hsts-off` + `ocsp-off` + the A+ cap). NSHC
  is authoritative on the SOURCE. On the FIELD NAME: NSHC
  reads `hstsmaxage`; every profile row in the real fixture carries
  `maxage`, never `hstsmaxage` (measured) - a genuine
  divergence between NSHC's own source line and this appliance's NITRO
  payload. NSHC's name is read first, the measured alias second, both
  behind named constants (`_HSTS_MAXAGE_FIELD_NSHC`,
  `_HSTS_MAXAGE_FIELD_MEASURED_ALIAS`). PARITY NOTE: this field
  ALIAS is a declared deviation from NSHC's literal source line, not from
  its behavior - carry it into the parity ledger.
- `cipherpriority` is now read (`field_token`, NSHC :228-230); a
  non-integer value flags `cipher-priority-invalid` and SKIPS the
  legacy-first test entirely, rather than testing the file's own row
  order. Gives `KENMERKEN["cipher-priority-invalid"]` its producer.
- `round()` replaces `int()` at both places a score is turned into an
  integer (PowerShell's `[int]` cast rounds half-to-even; Python's `int()`
  truncates) - matches NSHC's letter, not just its direction of error.
- The ECC-curve binding is a read gap ONLY for a file gap or an
  absent parent (never for "present, confirmed zero rows") - NSHC's
  `$criticalReads` does not list it at all, and `Get-NshcSslVserverFacts`
  leaves `eccCurves` empty (kexPct 100) on a confirmed-empty response.
  That same parent-absent-vs-confirmed-empty distinction is what makes this correct rather than an
  over-correction: a vserver that legitimately binds no ECC curve now
  grades a letter instead of NIET BEOORDEELD.
- Two new tests pin `hstsMinAge` and the A+ threshold together - one
  landing on A+ with a compliant max-age, its sibling changing ONLY the
  max-age to `hstsMinAge - 1` and asserting the A+->A cap with kenmerk
  "hsts maxage te laag".
- A `certGate` cap value outside the pinned `LETTERS` vocabulary now
  raises where the gate is read, matching `_cap()`'s existing behaviour for
  the same class of bad ruleset value (previously `expiredCapsTo` had no
  check at all and would have become a silent seventh letter).

TWO FIELD-LEVEL FIXES from the FIRST implementation, unaffected by the
review above: `daystoexpiration` and `publickeysize` arrive as JSON INTEGERS on the
real fixture (measured), and `field_text()` returns "" for any non-string on
purpose - reading them with `field_text` would be a DEAD GUARD. Both are read
through `field_token`.

There is one kenmerk this product adds that NSHC has no flag for:
"tls1.3 uit". It carries NO weight in the score (the score follows NSHC
exactly); it is there because "geen TLS 1.3" is the first thing a reader asks
about and silence would be worse than a word.

A follow-up review
found one Critical and one Important; the measurement and the mutation
RED/GREEN for each are written out at the finding itself below.

- An unexpanded profile cipher GROUP (its own expansion file absent,
  or this specific group missing from an otherwise-fine file) now flags
  "cipher-group-not-expanded" EXPLICITLY, for ANY group name - not only
  when the name coincidentally matches `defaultCipherGroupNames`
  (`_cipher_percent`'s pre-existing, name-based check, kept only for the
  LEGACY vserver-DEFAULT path and made idempotent against this one). It
  also contributes NOTHING to the cipher score any more (never the
  group's own NAME standing in as a best-case cipher) - NSHC never treats
  a group name as a cipher name either, so an unexpandable group there
  simply leaves $cipherEntries empty; matched here via `_cipher_percent`'s
  existing "no names" branch (flag "default-cipher-group", cipherPct 50).
  This is true of the PROFILE path, and of that path only. See the
  note below on the LEGACY vserver path for why it scores
  the group name at 100 instead - NSHC does the same, and the two paths
  diverge in NSHC itself.
  Separately, a GENUINE read gap on the group's own expansion file (hash
  mismatch, bad shape, ...) - as opposed to the file simply never being
  carried - now drops the vserver to NIET BEOORDEELD
  (`missing.append(CIPHER_GROUP_BINDING)`) instead of silently falling
  into the same lenient "unexpanded" branch. Read via
  `export.grouped_bindings()` directly for this one lookup (the same
  parent-absent-vs-confirmed-empty mechanism `_parents()` wraps for the
  other four by-parent files, which
  do not need this distinction because ANY gap on them already means NIET
  BEOORDEELD) - not a second mechanism.
- Two new tests gate the `cipherpriority` SORT (file order reversed against
  `cipherpriority`) and its SKIP-when-unreliable behaviour (a weak cipher
  first in file order with a non-integer priority) by mutation - both
  previously left the full suite green when removed.

On the LEGACY vserver path: the LETTER follows NSHC; the CERTAINTY is
this product's own.

MEASURED on the real fixture: VSRV-003 and VSRV-002 have no sslprofile,
one ciphersuite-binding row each carrying the group name DEFAULT, and no
expansion file. The round before this one stripped that name out of the
cipher list before scoring, so both landed on cipherPct 50 -> score 44 ->
letter F. NSHC, on the SAME data, gives C 64: its legacy per-vserver path
puts the binding rows straight into its cipher list and reaches its own
50-branch only when that list is EMPTY. One entry that matches no weak
pattern scores 100 there. NSHC expands a group ONLY on the profile path,
through config/sslcipher_binding/<group>.

So this product was two letters STRICTER than the healthcheck it mirrors,
on a score (44) no healthcheck produces - and it printed that letter as
[vastgesteld] over a cipher list nothing had ever read. Both halves were
wrong, and they are fixed in opposite directions: parity restores the
letter, and a ReadGap on the grade takes the [vastgesteld] off it. The
reader sees C (score 64) [niet vastgesteld], an evidence clause saying the
group was not expanded and that the letter follows the NSHC rule, and the
same sentence again under NIET VASTGESTELD. Nothing is invented in either
direction: not a score, and not a certainty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.knowledge import Knowledge
from nsmcp.rulesets import SSL_BASELINE, ruleset_line
from nsmcp.ssl_precedence import field_text, field_token, profile_index, resolve

VSERVER_RESOURCE = "config/sslvserver"
PROFILE_RESOURCE = "config/sslprofile"
CERT_RESOURCE = "config/sslcertkey"
CIPHER_BINDING = "sslvserver_sslciphersuite_binding.by-parent.json"
ECC_BINDING = "sslvserver_ecccurve_binding.by-parent.json"
CERT_BINDING = "sslvserver_sslcertkey_binding.by-parent.json"
# The cipher source for a PROFILE-managed vserver (NSHC :193-232). Keyed
# by the PROFILE name, not the vserver name - `_parents()` groups on the
# by-parent file's OWN declared parent identity, so the same helper serves
# both shapes without knowing which field means "parent" in each file.
PROFILE_CIPHER_BINDING = "sslprofile_sslcipher_binding.by-parent.json"
# The cipher GROUP's own expansion (NSHC: config/sslcipher_binding/<group>,
# :210-217). Not present in the real fixture (measured 2026-09-06/07) - this
# module reads it defensively for the day an export does carry it; until
# then every profile-bound cipher group falls to the "unexpanded group name"
# branch and scores 50 - which is what NSHC scores there, because NSHC's
# profile path expands the group through THIS file and finds nothing. The
# LEGACY vserver path is deliberately NOT the same case: NSHC never expands
# there, so a group name scores 100 (see below).
CIPHER_GROUP_BINDING = "sslcipher_binding.by-parent.json"

# NSHC's OWN field name for the HSTS max-age (Invoke-NshcSslGrade.ps1:176)
# is read FIRST, for parity. The real fixture never carries it (measured:
# every ns_default_ssl_profile_* row carries `maxage`, never
# `hstsmaxage`) - the measured alias is read SECOND. This is a declared
# deviation from NSHC's literal source line (not from its behaviour); see
# the module docstring's HSTS entry and the parity ledger.
_HSTS_MAXAGE_FIELD_NSHC = "hstsmaxage"
_HSTS_MAXAGE_FIELD_MEASURED_ALIAS = "maxage"

# NSHC's isEcc gate (defined Invoke-NshcSslGrade.ps1:278, consumed in
# the weak-key gate at :388) matches signaturealg only; this also matches
# `publickey` (a second, independent ECC signal present in the real
# fixture's sslcertkey rows, e.g. "ecPublicKey" next to RSA's
# "rsaEncryption") - measured to be needed for a P-256
# certificate.
_ECC_KEY_PATTERN = re.compile(r"(?i)ecdsa|ecpublickey")

LETTERS = ("A+", "A", "B", "C", "F", "T")
# NIET BEOORDEELD is GEEN letter (ontwerp 2.2 rij A6: "letter per vserver uit precies
# deze zes"). Het is het woord dat in de plaats van een letter komt zodra een kritieke
# bron niet gelezen is - en het staat daarom apart, zodat een lus over LETTERS nooit
# per ongeluk een leesgat als grade meetelt.
NOT_ASSESSED_WORD = "NIET BEOORDEELD"
_CAP_ORDER = ("A+", "A", "B", "C", "F", "T")

# The Dutch word per NSHC flag. Product surface: pinned by
# tests/test_product_surface.py and by tests/test_tls_baseline.py.
KENMERKEN = {
    "ssl3-enabled": "ssl3 aan",
    "tls10-enabled": "tls1.0 aan",
    "tls11-enabled": "tls1.1 aan",
    "no-tls13": "tls1.3 uit",
    "weak-cipher": "zwakke cipher",
    "legacy-cipher-first": "zwakke cipher vooraan",
    "cipher-priority-invalid": "cipher-volgorde onbetrouwbaar",
    "default-cipher-group": "geen expliciete ciphers",
    "cipher-group-not-expanded": "ciphergroep niet uitgesplitst",
    "p224-present": "p224 curve",
    "hsts-off": "hsts uit",
    "hsts-maxage-too-low": "hsts maxage te laag",
    "ocsp-off": "ocsp-stapling uit",
    "expired-cert": "verlopen certificaat",
    "weak-key": "zwakke sleutel",
    "no-server-cert-bound": "geen servercert gebonden",
}

# The two sentences that carry an unexpanded cipher group.
# The first is a clause on the finding's OWN evidence line, so the letter is
# never read without it; the second is the ReadGap reason, which also lands
# under "NIET VASTGESTELD". Deliberately WITHOUT the group's own name: that
# name comes off the export, and `names_in_tls_sources()` guarantees it
# never reaches a reason or an evidence string.
# NO group name in this sentence, and that is the whole point of the two
# lines above. It used to read "ciphergroep DEFAULT niet uitgeklapt":
# true on the real fixture, and a FABRICATION anywhere else - the legacy
# path also fires on DEFAULT_BACKEND, and the profile path fires on ANY
# group name at all. That would print a name this product never read, in
# the one sentence whose whole job is to say that something was not read.
_UNEXPANDED_GROUP_EVIDENCE = "ciphergroep niet uitgeklapt; letter volgens de NSHC-regel"
_UNEXPANDED_GROUP_REASON = (
    "de gebonden ciphergroep is in deze export niet uitgeklapt, dus de ciphers"
    " zelf zijn niet gelezen; de letter volgt de NSHC-regel"
)

NOT_ASSESSED = (
    NotAssessed(
        subject="werkelijke handshake",
        reason=(
            "dit is een configuratieweging, geen live scan: wat de appliance in een echte"
            " handshake aanbiedt - ketenvolgorde, OCSP-stapling in de praktijk - is hiermee"
            " niet bewezen"
        ),
    ),
)


@dataclass(frozen=True)
class Grade:
    vserver: str
    letter: str
    score: int | None
    source: str
    kenmerken: tuple[str, ...] = ()
    reason: str = ""
    # The same read_gap pattern as ha.HaDimension.read_gap: the
    # LETTER stays what NSHC computes, the CERTAINTY does not. One field,
    # two consumers (the finding's marker and the answer's own read_gaps
    # list) - never a second return channel next to Grade.
    read_gap: ReadGap | None = None


def _parents(export, file_name: str) -> dict[str, list[dict] | None]:
    """parentName -> its binding rows, for a by-parent file - a THREE-WAY
    result, not two.

    A key ABSENT from this dict means the parent was never read at all (the
    whole file unreadable, or this specific parent missing from it) - the
    caller turns THAT into a read gap. A key present with value `None`
    means the parent WAS read and is a CONFIRMED emptiness (NSHC's
    three-way distinction, Invoke-NshcSslGrade.ps1:243-253: a response
    present with 0 bindings is a BEVINDING, never a leesgat) - never
    treated as missing. A key present with a list is that parent's real
    rows, possibly itself empty in content but not in kind.
    """
    grouped, gap = export.grouped_bindings(file_name)
    if gap is not None:
        return {}
    return grouped


def _server_cert_names(rows: list[dict]) -> list[str]:
    """The certkeyname of every row that is a SERVER certificate binding -
    mirrors NSHC's Test-NshcIsServerCertBinding (Invoke-NshcSslGrade.ps1:
    84-95): skip an empty certkeyname, and skip `ca` true (both the JSON
    bool and the string shape, via `field_token`) - a ca=true binding is
    client-certificate VALIDATION, not a server identity, and counting it
    would show a vserver without a server certificate as "heeft cert".
    `snicert` is NOT filtered on: an snicert=true binding is still a real
    server certificate.
    """
    names: list[str] = []
    for row in rows:
        certkey = field_text(row, "certkeyname")
        if not certkey:
            continue
        if field_token(row, "ca").casefold() == "true":
            continue
        names.append(certkey)
    return names


def _group_name(row: dict) -> str:
    """The cipher GROUP name a profile's cipher-binding row carries - NSHC's
    own fallback chain, lab-confirmed field first (Invoke-NshcSslGrade.ps1:
    205-209): `cipheraliasname`, then `ciphername`, then `ciphergroupname`.
    """
    return field_text(row, "cipheraliasname") or field_text(row, "ciphername") or field_text(row, "ciphergroupname")


def _is_ecc_cert(cert: dict) -> bool:
    """NSHC's isEcc gate. An ECC certificate is never flagged as a weak
    RSA key - publicKeySize does not mean the same thing for an ECC key."""
    return bool(_ECC_KEY_PATTERN.search(field_token(cert, "signaturealg"))) or bool(
        _ECC_KEY_PATTERN.search(field_token(cert, "publickey"))
    )


def _profile_only(row: dict, index: dict, field: str) -> str | None:
    """The PROFILE-ONLY value of `field` - NSHC's own hsts/ocspStapling/
    hstsMaxAge rule (Invoke-NshcSslGrade.ps1:142,167-171,174-176): filled
    ONLY from a bound-and-read profile, NEVER from the vserver's own field.
    With no profile bound this stays unset (`None`) - unlike
    `ssl_precedence.resolve()`'s generic no-profile branch, which returns
    the VSERVER's own value (correct for protocol; wrong for HSTS/OCSP,
    for the same reason).
    `resolve()` is reused only for its profile_bound/profile_read STATE;
    its `value` is deliberately discarded in the no-profile branch, so
    `ssl_precedence.py` itself needs no change - the "one resolver" rule
    is kept by using its state, not by bending its return value.
    """
    found = resolve(row, index, field)
    if not found.profile_bound or not found.profile_read:
        return None
    # `resolve()` is reused only for its
    # profile_bound/profile_read STATE (see the docstring above) - its
    # `.value` comes from `field_text()`, correct for the ENABLED/DISABLED
    # fields this function also serves (hsts, ocspstapling) but a DEAD
    # GUARD for `hstsmaxage`/`maxage`, a NUMBER on this same resource
    # (`sslprofile` already mixes types on the real fixture - `cleartextport`
    # is a JSON int). Re-read the field with `field_token` directly off the
    # profile row instead of trusting `resolve()`'s text-only value; for the
    # genuinely-string fields this returns the identical text `field_text`
    # would (`field_token` is a strict superset for a plain string).
    profile_row = index.get(found.profile_name.casefold())
    value = field_token(profile_row, field) if profile_row is not None else ""
    return value.upper() if value else None


def _protocol_percent(get, flags: list[str]) -> int | None:
    values = {name: get(name) for name in ("ssl3", "tls1", "tls11", "tls12", "tls13")}
    if any(value is None for value in values.values()):
        return None
    if values["ssl3"] == "ENABLED":
        flags.append("ssl3-enabled")
    if values["tls1"] == "ENABLED":
        flags.append("tls10-enabled")
    if values["tls11"] == "ENABLED":
        flags.append("tls11-enabled")
    if values["tls13"] != "ENABLED":
        flags.append("no-tls13")
    if values["ssl3"] == "ENABLED" or values["tls1"] == "ENABLED":
        return 20
    if values["tls11"] == "ENABLED":
        return 50
    if values["tls12"] == "ENABLED" or values["tls13"] == "ENABLED":
        return 100
    return 0


def _cipher_percent(rows: list[dict], flags: list[str]) -> int:
    """The cipher score for one vserver, from its RAW binding rows (not
    pre-extracted names - the priority sort below needs `cipherpriority`
    per row, which a bare name list cannot carry).
    """
    rules = SSL_BASELINE.rules
    names = [field_text(b, "ciphername") for b in rows if field_text(b, "ciphername")]
    if (
        any(name.upper() in rules["defaultCipherGroupNames"] for name in names)
        and "cipher-group-not-expanded" not in flags
    ):
        # An honest note, not a penalty: the export carries the GROUP name, not
        # its members, so the individual ciphers of that group were not read.
        # NSHC scores this the same way; saying nothing about it would let a
        # reader believe every cipher was inspected. This is the LEGACY
        # vserver-DEFAULT path's own detection (by name, on `rows` straight
        # off the per-vserver ciphersuite binding); the `not in flags` guard
        # keeps it idempotent next to the explicit, name-independent flag
        # for the profile-cipher-GROUP path (grade_per_vserver, above) - the
        # two must never print the same kenmerk twice for one vserver.
        flags.append("cipher-group-not-expanded")
    # The group NAME deliberately STAYS in `names`. The
    # earlier version stripped it here so that a vserver carrying only the
    # group name fell into the 50-branch below. Measured against NSHC on
    # identical input, that made this product land two letters lower than
    # the healthcheck it mirrors: F 44 where NSHC gives C 64.
    #
    # NSHC's LEGACY per-vserver path (Invoke-NshcSslGrade.ps1, the
    # ciphersuite-binding read and the score block) puts the binding rows
    # straight into its cipher list and reaches its own 50-branch ONLY
    # when that list is EMPTY. A group name in the list is one entry, does
    # not match a weak pattern, and therefore scores 100 there.
    #
    # Parity wins on the LETTER. What this product owes on top of it is
    # not a quietly different score - a fabricated 44 is as much an
    # invention as a silent 100 - but a visible statement that the group's
    # members were never read: the `cipher-group-not-expanded` kenmerk
    # above, plus the ReadGap `grade_per_vserver` hangs on it, which takes
    # the `[vastgesteld]` off this vserver's letter (the same read_gap
    # pattern as ha.HaDimension.read_gap). The PROFILE path is a different case and
    # keeps its 50: NSHC expands a profile-bound group through its own
    # binding file and lands on 50 exactly when that expansion yields
    # nothing - which is what this module does there too.
    if not names:
        flags.append("default-cipher-group")
        return 50
    weak = [name for name in names if any(re.search(p, name) for p in rules["weakCipherPatterns"])]
    # round(), not int() - PowerShell's [int] cast rounds half-to-even;
    # Python's int() truncates. Measured: 64.8 rounds to 65 (letter B) in
    # NSHC, truncates to 64 (letter C) with int().
    percent = round(100 * (1 - len(weak) / len(names)))
    if weak:
        flags.append("weak-cipher")
        percent = min(percent, 40)
    # cipherpriority (Invoke-NshcSslGrade.ps1:228-230,341-347). NSHC
    # sorts the cipher entries by it and, when ANY value on this vserver is
    # non-numeric, sets cipherPriorityReliable=false, flags
    # cipher-priority-invalid and SKIPS the legacy-first test entirely -
    # never tests the file's own row order as a stand-in for priority.
    priority_rows = [b for b in rows if field_text(b, "ciphername")]
    priorities = [field_token(b, "cipherpriority") for b in priority_rows]
    priority_reliable = all(p.lstrip("-").isdigit() for p in priorities)
    if not priority_reliable:
        flags.append("cipher-priority-invalid")
    else:
        ordered = sorted(priority_rows, key=lambda b: int(field_token(b, "cipherpriority")))
        first_name = field_text(ordered[0], "ciphername")
        if any(re.search(p, first_name) for p in rules["weakCipherPatterns"]):
            flags.append("legacy-cipher-first")
            percent = min(percent, 40)
    return percent


def _kex_percent(curves: list[str], flags: list[str]) -> int:
    forbidden = [c for c in curves if c.upper() in SSL_BASELINE.rules["forbiddenEccCurves"]]
    if forbidden:
        flags.append("p224-present")
        return 60
    return 100


def _letter_for(score: int) -> str:
    thresholds = SSL_BASELINE.rules["gradeThresholds"]
    if score >= thresholds["Aplus"]:
        return "A+"
    if score >= thresholds["A"]:
        return "A"
    if score >= thresholds["B"]:
        return "B"
    if score >= thresholds["C"]:
        return "C"
    return "F"


def _cap(letter: str, cap: str) -> str:
    return cap if _CAP_ORDER.index(letter) < _CAP_ORDER.index(cap) else letter


def grade_per_vserver(export) -> tuple[Grade, ...]:
    vservers, vserver_gap = export.objects(VSERVER_RESOURCE)
    if vserver_gap is not None:
        return ()
    profiles, profile_gap = export.objects(PROFILE_RESOURCE)
    index = profile_index(profiles if profile_gap is None else [])
    certs, cert_gap = export.objects(CERT_RESOURCE)
    by_certkey = {field_text(c, "certkey"): c for c in certs if isinstance(c, dict) and field_text(c, "certkey")}
    vserver_ciphers = _parents(export, CIPHER_BINDING)
    profile_cipher_groups = _parents(export, PROFILE_CIPHER_BINDING)
    # The other four by-parent lookups above always
    # turn "parent absent" into NIET BEOORDEELD via the `missing.append(...)`
    # checks below, so `_parents()`'s collapse of ANY read gap to `{}` is
    # harmless for them - broken or simply-absent, the outcome is identical.
    # CIPHER_GROUP_BINDING is the ONE lookup with an honest fallback for
    # "absent" (the unexpanded group name stands in as one entry, below) -
    # so a GENUINE read gap on THIS file (hash mismatch, bad shape, ...)
    # must not silently collapse into that same lenient fallback. This
    # reads export.grouped_bindings() directly - the SAME mechanism
    # `_parents()` already wraps, just without discarding the gap - rather
    # than inventing a second one.
    cipher_groups, cipher_group_gap = export.grouped_bindings(CIPHER_GROUP_BINDING)
    cipher_group_declared = f"bindings/{CIPHER_GROUP_BINDING}" in export.file_hashes
    cipher_group_broken = cipher_group_gap is not None and cipher_group_declared
    if cipher_group_gap is not None:
        cipher_groups = {}
    curves = _parents(export, ECC_BINDING)
    cert_bindings = _parents(export, CERT_BINDING)

    gate = SSL_BASELINE.rules["certGate"]
    # A certGate cap value outside the pinned letter vocabulary must
    # never become a silent seventh letter - `_cap()` already raises on
    # this class of value for weakKeyCapsTo; expiredCapsTo had no check at
    # all (it is assigned to `letter` with no membership test). Made
    # consistent here, where the gate is READ, once per grading pass.
    if gate["expiredCapsTo"] not in LETTERS or gate["weakKeyCapsTo"] not in LETTERS:
        raise ValueError(
            "certGate-capwaarde buiten het gepinde letterwoordenboek LETTERS:"
            f" expiredCapsTo={gate['expiredCapsTo']!r}, weakKeyCapsTo={gate['weakKeyCapsTo']!r}"
        )

    grades: list[Grade] = []
    for row in vservers:
        if not isinstance(row, dict):
            continue
        name = field_text(row, "vservername") or field_text(row, "name")
        flags: list[str] = []

        def get(field: str, _row=row) -> str | None:
            found = resolve(_row, index, field)
            if found.profile_bound and not found.profile_read:
                return None
            return found.value.upper() if found.value else None

        # THE HARD READ RULE, isolated once per vserver: any field query
        # against `row` reports the SAME profile_bound/profile_read pair
        # (both derive only from the vserver's own `sslprofile` field and
        # whether that name is in the read profile list - never from which
        # field was asked), so a single resolve() call here tells us
        # whether "protocol is None" below means "a bound profile was not
        # read" (name it specifically) or something else (a plain
        # config/sslvserver or config/sslprofile data problem). The cipher
        # source below reuses this SAME state to route the cipher source too.
        protocol_source = resolve(row, index, "tls12")
        source = protocol_source.source
        protocol = _protocol_percent(get, flags)
        missing: list[str] = []
        if protocol is None:
            if protocol_source.profile_bound and not protocol_source.profile_read:
                missing.append(
                    f"gebonden SSL-profiel {protocol_source.profile_name} staat niet in de gelezen profiellijst"
                )
            elif protocol_source.profile_bound:
                # The profile WAS read, but could not establish every
                # protocol field - a config/sslprofile data problem, not a
                # vserver one.
                missing.append(PROFILE_RESOURCE)
            else:
                missing.append(VSERVER_RESOURCE)

        # With a profile bound and READ, ciphers come from the cipher
        # GROUP bound to the PROFILE - never from the legacy per-vserver
        # ciphersuite binding, even when one is present (NSHC :193-232). A
        # bound-but-unread profile already names its OWN missing reason
        # above (protocol needs the identical profile read); no second,
        # duplicate reason is added here for that case.
        cipher_rows: list[dict] | None
        if protocol_source.profile_bound:
            if not protocol_source.profile_read:
                cipher_rows = None
            elif protocol_source.profile_name not in profile_cipher_groups:
                missing.append(PROFILE_CIPHER_BINDING)
                cipher_rows = None
            else:
                cipher_rows = []
                group_not_expanded = False
                for group_row in profile_cipher_groups[protocol_source.profile_name] or []:
                    gname = _group_name(group_row)
                    if not gname:
                        continue
                    if gname in cipher_groups:
                        group_rows = cipher_groups[gname]
                        if group_rows is not None:
                            cipher_rows.extend(group_rows)
                        # else: outcome EMPTY for this group (the
                        # three-way distinction `_parents()` draws) - a CONFIRMED zero
                        # members, not an unexpanded one; contributes
                        # nothing and does not set group_not_expanded.
                    else:
                        # The export does not carry (or does not read) the
                        # group's own expansion file, or this specific
                        # group has no parent entry in an otherwise-fine
                        # file. This group's REAL members were never
                        # established, so it contributes NOTHING to
                        # cipher_rows (never the group's own NAME standing
                        # in as if it were a cipher) - NSHC never treats a
                        # group name as a cipher name either; an
                        # unexpandable group there simply leaves
                        # $cipherEntries empty. If every bound group ends
                        # up here, `_cipher_percent([])` below scores this
                        # EXACTLY like NSHC's empty-$cipherEntries case
                        # (flag "default-cipher-group", cipherPct 50) -
                        # never the silent best-case 100 the group's own
                        # name coincidentally not matching a weak pattern
                        # used to produce.
                        group_not_expanded = True
                if group_not_expanded:
                    if cipher_group_broken:
                        # The expansion file IS declared
                        # in the manifest but could not be trusted (hash
                        # mismatch, bad shape, wrong bindingResource, ...)
                        # - a genuine ReadGap, not the honest "this export
                        # simply never carries it" case. Never silently
                        # score the unexpanded placeholder as if it were
                        # a real, best-case cipher.
                        missing.append(CIPHER_GROUP_BINDING)
                    else:
                        # Flag this EXPLICITLY, for ANY
                        # group name - not only when the placeholder name
                        # happens to be "DEFAULT"/"DEFAULT_BACKEND"
                        # (`_cipher_percent`'s pre-existing, name-based
                        # check, kept for the LEGACY vserver-DEFAULT path
                        # below and made idempotent so the two mechanisms
                        # never print the same kenmerk twice).
                        flags.append("cipher-group-not-expanded")
        else:
            if name not in vserver_ciphers:
                missing.append(CIPHER_BINDING)
                cipher_rows = None
            else:
                cipher_rows = vserver_ciphers[name] or []

        # The ECC-curve binding is a read gap ONLY for "parent absent"
        # (this check) or a whole-file gap (folded into `_parents()`
        # returning `{}`) - never for "parent present, confirmed zero
        # rows", which `_parents()`'s three-way distinction already tells apart.
        if name not in curves:
            missing.append(ECC_BINDING)
        if name not in cert_bindings:
            missing.append(CERT_BINDING)
        if cert_gap is not None:
            missing.append(CERT_RESOURCE)
        else:
            # Evaluate the bound certificates BEFORE the missing/continue
            # decision - NSHC's sslcertkey / sslcertkey.daystoexpiration /
            # sslcertkey.publickeysize critical reads (Invoke-NshcSslGrade.
            # ps1:264,271-272,305). An absent certkey object or a
            # non-integer daystoexpiration/publickeysize must drop the
            # vserver to NIET BEOORDEELD - never silently "not expired, not
            # weak", which is what `by_certkey.get(certkey, {})` used to do.
            for certkey in _server_cert_names(cert_bindings.get(name) or []):
                cert = by_certkey.get(certkey)
                if cert is None:
                    missing.append(CERT_RESOURCE)
                    continue
                if not field_token(cert, "daystoexpiration").lstrip("-").isdigit():
                    missing.append(f"{CERT_RESOURCE}.daystoexpiration")
                if not field_token(cert, "publickeysize").isdigit():
                    missing.append(f"{CERT_RESOURCE}.publickeysize")

        if missing:
            grades.append(
                Grade(
                    vserver=name,
                    letter=NOT_ASSESSED_WORD,
                    score=None,
                    source=source,
                    reason="kritieke bron niet bruikbaar gelezen: " + ", ".join(sorted(set(missing))),
                )
            )
            continue

        curve_names = [field_text(b, "ecccurvename") for b in (curves[name] or []) if field_text(b, "ecccurvename")]
        cipher = _cipher_percent(cipher_rows or [], flags)
        kex = _kex_percent(curve_names, flags)
        weights = SSL_BASELINE.rules["weights"]
        score = round(
            (protocol * weights["protocol"] + kex * weights["keyExchange"] + cipher * weights["cipher"]) / 100
        )
        letter = _letter_for(score)

        # hsts/ocsp/hsts-max-age come ONLY from a bound-and-read
        # profile (NSHC :142,167-171,174-176) - never from the vserver's
        # own fields, unlike protocol. With no profile bound both stay
        # unset (None), which the checks below already read as "off".
        hsts = _profile_only(row, index, "hsts")
        ocsp = _profile_only(row, index, "ocspstapling")
        max_age_text = (
            _profile_only(row, index, _HSTS_MAXAGE_FIELD_NSHC)
            or _profile_only(row, index, _HSTS_MAXAGE_FIELD_MEASURED_ALIAS)
            or "0"
        )
        if hsts != "ENABLED":
            flags.append("hsts-off")
        elif not max_age_text.isdigit() or int(max_age_text) < SSL_BASELINE.rules["hstsMinAge"]:
            flags.append("hsts-maxage-too-low")
        if "hsts-off" in flags or "hsts-maxage-too-low" in flags:
            if letter == "A+":
                letter = "A"
        if ocsp != "ENABLED":
            flags.append("ocsp-off")

        # Skip an empty certkeyname and a ca=true binding (client-cert
        # validation, not a server identity) - _server_cert_names() is the
        # SAME filter the pre-check above already applied.
        bound = _server_cert_names(cert_bindings[name] or [])
        if not bound:
            flags.append("no-server-cert-bound")
            letter = "T"
        else:
            expired, weak_key = False, False
            for certkey in bound:
                cert = by_certkey.get(certkey, {})
                # Measured on the real fixture:
                # daystoexpiration and publickeysize arrive as JSON
                # INTEGERS, not strings. field_text() returns "" for any
                # non-string on purpose (it feeds paths and evidence) - it
                # is a DEAD GUARD here. field_token reproduces the value as
                # PowerShell's own [string] cast would, exactly like NSHC.
                days = field_token(cert, "daystoexpiration")
                size = field_token(cert, "publickeysize")
                if days.lstrip("-").isdigit() and int(days) <= 0:
                    expired = True
                # An ECC certificate is never a weak RSA key.
                if size.isdigit() and int(size) < gate["minRsaBits"] and not _is_ecc_cert(cert):
                    weak_key = True
            if expired:
                flags.append("expired-cert")
                letter = gate["expiredCapsTo"]
            elif weak_key:
                flags.append("weak-key")
                letter = _cap(letter, gate["weakKeyCapsTo"])

        grades.append(
            Grade(
                vserver=name,
                letter=letter,
                score=score,
                source=source,
                kenmerken=tuple(KENMERKEN[flag] for flag in flags),
                # `flags` is complete here (hsts, ocsp and the certificate gate
                # have all had their say), and the flag is set on BOTH paths:
                # by `_cipher_percent` for the legacy vserver binding and by
                # this function itself for the profile-bound group.
                read_gap=(
                    ReadGap(source=name, reason=_UNEXPANDED_GROUP_REASON)
                    if "cipher-group-not-expanded" in flags
                    else None
                ),
            )
        )
    return tuple(grades)


def tls_baseline(export, knowledge: Knowledge) -> Answer:
    grades = grade_per_vserver(export)
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []
    for grade in grades:
        if grade.letter == NOT_ASSESSED_WORD:
            findings.append(
                Finding(
                    subject=grade.vserver,
                    outcome=NOT_ASSESSED_WORD,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{VSERVER_RESOURCE} (bron: {grade.source})",
                    reason=grade.reason,
                )
            )
            read_gaps.append(ReadGap(source=grade.vserver, reason=grade.reason))
            continue
        # The letter is NSHC's; the marker is this
        # product's own discipline. A letter computed over a cipher group
        # whose members were never read may not stand as [vastgesteld], so
        # the read gap the grade carries takes the marker down and says, on
        # the evidence line itself, why the letter still reads as it does.
        evidence = f"{VSERVER_RESOURCE} + bindingen (bron: {grade.source})"
        if grade.read_gap is not None:
            evidence = f"{evidence}; {_UNEXPANDED_GROUP_EVIDENCE}"
        findings.append(
            Finding(
                subject=grade.vserver,
                outcome=f"{grade.letter} (score {grade.score})",
                certainty=(Certainty.ESTABLISHED if grade.read_gap is None else Certainty.NOT_ESTABLISHED),
                evidence=evidence,
                # `Finding` demands a reason for a non-established certainty.
                # The kenmerken always carry the unexpanded-group one when a
                # gap exists; the fallback mirrors ha.to_finding().
                reason=", ".join(grade.kenmerken) or grade.read_gap.reason,
            )
        )
        if grade.read_gap is not None:
            read_gaps.append(grade.read_gap)

    # config/sslvserver itself can be an unreadable resource, which
    # `grade_per_vserver()` reports as `()` - the SAME empty result a
    # genuinely-zero-vservers export gives. The two are told apart HERE, by
    # reading the resource a second time (the same "ask twice, tell two
    # questions apart" idiom as export.py's bindings()/binding_parents()
    # pair): "[vastgesteld]" may never stand over an unread source, and the
    # genuinely-empty case gets its own wording rather than sharing one
    # that reads as "not read" either way.
    _, vserver_gap = export.objects(VSERVER_RESOURCE)
    if vserver_gap is not None:
        findings.append(
            Finding(
                subject="gradeverdeling",
                outcome=NOT_ASSESSED_WORD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"{VSERVER_RESOURCE}: niet bruikbaar gelezen",
                reason=vserver_gap.reason,
                subject_is_name=False,
            )
        )
        read_gaps.append(ReadGap(source=VSERVER_RESOURCE, reason=vserver_gap.reason))
    else:
        tally: dict[str, int] = {}
        for grade in grades:
            tally[grade.letter] = tally.get(grade.letter, 0) + 1
        spread = ", ".join(f"{tally[letter]}x {letter}" for letter in LETTERS + (NOT_ASSESSED_WORD,) if letter in tally)
        findings.append(
            Finding(
                subject="gradeverdeling",
                outcome=spread or "geen enkele sslvserver gevonden",
                certainty=Certainty.ESTABLISHED,
                evidence=f"{VSERVER_RESOURCE}: {len(grades)} virtuele servers",
                subject_is_name=False,
            )
        )
    findings.append(
        Finding(
            subject="regelset",
            outcome=f"{SSL_BASELINE.name} {SSL_BASELINE.version}",
            certainty=Certainty.ESTABLISHED,
            evidence=ruleset_line(SSL_BASELINE),
            subject_is_name=False,
        )
    )
    return Answer(
        question="welke TLS-instellingen wijken af van de baseline",
        findings=findings,
        read_gaps=read_gaps,
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


@dataclass(frozen=True)
class BaselineCriterion:
    """One NSHC L1-010 criterion, independent of the per-vserver grade."""

    criterion: str
    status: str
    evidence: str
    read_gaps: tuple[ReadGap, ...] = ()


@dataclass(frozen=True)
class BaselineResult:
    criteria: tuple[BaselineCriterion, ...]

    @property
    def status(self) -> str:
        if any(c.status == "FAIL" for c in self.criteria):
            return "FAIL"
        if any(c.status == NOT_ASSESSED_WORD for c in self.criteria):
            return NOT_ASSESSED_WORD
        return "PASS"

    @property
    def read_gaps(self) -> tuple[ReadGap, ...]:
        return tuple(g for c in self.criteria for g in c.read_gaps)


def baseline_result(export) -> BaselineResult:
    """NSHC L1-010, not a second grader: protocols plus ALL certificates.

    Shared profile precedence and expiry thresholds are authoritative. Absent
    SSLv2 (including the measured profile limitation) never establishes PASS.
    This helper leaves the public TLS grade answer byte-for-byte unchanged.
    """
    from nsmcp.expiry import _SIGNATURE_ALG_PATTERN, bucket
    from nsmcp.export import MISSING, shape_or_missing

    vservers, vg = export.objects(VSERVER_RESOURCE)
    profiles, pg = export.objects(PROFILE_RESOURCE)
    certificates, cg = export.objects(CERT_RESOURCE)
    index = profile_index(profiles)
    criteria = []

    def gap_for(row, key, source):
        return ReadGap(
            source=source, reason=f"veld {key} niet bruikbaar gelezen ({shape_or_missing(row.get(key, MISSING))})"
        )

    def signature_kind(raw):
        # First the existing canonical shape gate, then COMPLETE supported
        # algorithm names. A known substring inside an unknown algorithm
        # proves neither its digest strength nor its public-key family.
        if not isinstance(raw, str) or not _SIGNATURE_ALG_PATTERN.fullmatch(raw):
            return None
        name = raw.casefold()
        if re.fullmatch(r"(?:md5|sha(?:1|224|256|384|512))withrsaencryption", name):
            return "rsa"
        if re.fullmatch(r"ecdsa-with-sha(?:1|224|256|384|512)", name):
            return "ecc"
        if re.fullmatch(r"dsa(?:-with-)?sha(?:1|224|256|384|512)", name) or name == "dsawithsha1":
            return "dsa"
        return None

    def finish(name, fails, gaps, count):
        criteria.append(
            BaselineCriterion(
                name,
                "FAIL" if fails else NOT_ASSESSED_WORD if gaps else "PASS",
                f"{name}: {count} objecten, {fails} vastgestelde afwijkingen",
                tuple(gaps),
            )
        )

    for key in ("ssl2", "ssl3", "tls1"):
        gaps = [vg] if vg else []
        fails = 0
        if not vservers and not gaps:
            gaps.append(
                ReadGap(source=VSERVER_RESOURCE, reason="gelezen maar geen SSL-vservers; protocolstand onbekend")
            )
        for row in vservers:
            bound = row.get("sslprofile", MISSING)
            # Absent reference is not proof that no overriding profile exists.
            if bound is MISSING or not isinstance(bound, str):
                gaps.append(gap_for(row, "sslprofile", VSERVER_RESOURCE))
                continue
            effective = resolve(row, index, key)
            source = PROFILE_RESOURCE if effective.profile_bound else VSERVER_RESOURCE
            owner = index.get(bound.casefold(), {}) if effective.profile_bound else row
            if effective.profile_bound and pg:
                gaps.append(pg)
                continue
            if effective.profile_bound and not effective.profile_read:
                gaps.append(ReadGap(source=PROFILE_RESOURCE, reason="gebonden profiel niet gelezen"))
                continue
            if effective.value.upper() == "ENABLED":
                fails += 1
            elif effective.value.upper() != "DISABLED":
                gaps.append(gap_for(owner, key, source))
        finish(key, fails, gaps, len(vservers))

    for key in ("daystoexpiration", "publickeysize", "signaturealg"):
        gaps = [cg] if cg else []
        fails = 0
        for cert in certificates:
            raw = cert.get(key, MISSING)
            if key == "daystoexpiration":
                classification = bucket(raw) if type(raw) in (int, float, str) else "unknown"
                if classification == "unknown":
                    gaps.append(gap_for(cert, key, CERT_RESOURCE))
                elif classification in ("expired", "critical", "warning"):
                    fails += 1
            elif key == "signaturealg":
                if signature_kind(raw) is None:
                    gaps.append(gap_for(cert, key, CERT_RESOURCE))
                elif re.search(r"sha1|md5", raw, re.I):
                    fails += 1
            else:
                signature = cert.get("signaturealg")
                kind = signature_kind(signature)
                if kind is None:
                    gaps.append(gap_for(cert, "signaturealg", CERT_RESOURCE))
                    continue
                if kind == "ecc":
                    continue
                text = str(raw) if type(raw) in (str, int) else ""
                if not re.fullmatch(r"\d{1,10}", text):
                    gaps.append(gap_for(cert, key, CERT_RESOURCE))
                elif int(text) < 2048:
                    fails += 1
        finish(key, fails, gaps, len(certificates))
    return BaselineResult(tuple(criteria))


def names_in_tls_sources(export) -> tuple[str, ...]:
    """Every appliance object name this answer can print - the ELEVENTH
    family of disclosure.names_from_export(): the sslvserver names, and the
    profile names that appear in the `bron:` field (including a profile
    name that was NEVER read - see the "gebonden SSL-profiel ... staat
    niet" reason text above, which prints it too).

    The profile's cipher-group binding added a new source, and the
    certificate-binding filter changed; NEITHER prints a new
    kind of name. The cipher GROUP name (`cipheraliasname` and its
    fallbacks) only ever feeds `_cipher_percent()`'s FIXED vocabulary
    (`KENMERKEN` values) - it never reaches a reason or an evidence string,
    so there is nothing new for this family to collect. Proven by hostile
    export in tests/test_tls_baseline.py
    (test_the_profile_cipher_group_name_is_never_printed). A certkey
    NAME is likewise never printed (the pre-existing reasons name
    only the fixed resource string `config/sslcertkey`, never a specific
    certkey).

    An sslvserver without a certificate binding (measured: VSRV-001) is
    known to the certificate families only by accident, and a custom SSL
    profile name is known to none of them at all.
    """
    names: set[str] = set()
    rows, gap = export.objects(VSERVER_RESOURCE)
    if gap is None:
        for row in rows:
            if isinstance(row, dict):
                for field in ("vservername", "name", "sslprofile"):
                    value = field_text(row, field)
                    if value:
                        names.add(value)
    profiles, profile_gap = export.objects(PROFILE_RESOURCE)
    if profile_gap is None:
        for row in profiles:
            if isinstance(row, dict) and field_text(row, "name"):
                names.add(field_text(row, "name"))
    return tuple(sorted(names))
