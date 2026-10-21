"""`rapport_na_upgrade` - the standalone half.

THE DEPENDENCY THIS MODULE DOES NOT MEET ON THIS BRANCH: the full design names
FOUR blocks - (1) per-source coverage of both exports side by side, via
the comparison engine; (2) the CVE verdict on the NEW build; (3) the
extra step the bulletin asks for after the upgrade, as its own check; (4)
the normalised configuration anchor plus the per-kind count of excluded
blob lines. Block 1 needs `compare.py` and `retention.py` wired in here -
both modules exist on this branch (they power `rapport_vergelijk` and the
export retention policy), but nothing in this module calls either of them
yet. This module builds blocks 2, 3 and 4 only. Block 1 is NOT invented
here: there will be exactly one comparison engine and exactly one "find
the previous export" mechanism in this product, and duplicating either
here would leave two implementations that can drift apart. Where block 1
would go, the answer carries a `NotAssessed`
entry instead (`BLOCK_ONE_SUBJECT`/`BLOCK_ONE_REASON` below) - never a
silent gap that reads as "nothing wrong", and never a `GERAAKT`/`NIET
GERAAKT` on data this module never read. The follow-up itself is written
down in `docs/klant/OPENSTAANDE-METINGEN.md`.

BLOCK 2, the CVE verdict on the NEW build, is not recomputed here: it is
`cve.cve_check(after, knowledge)`, called once and merged into this
module's own `Answer` (same findings, same read gaps, same `not_assessed`,
same vocabulary - `cve.GERAAKT`/`cve.NIET_GERAAKT`/`cve.NIET_VASTGESTELD`).
One engine, one call site. All THREE of those lists travel: dropping one of
them would be a silent omission in the one tool that exists to have none.

`cve_check(after, ...)` judges WHATEVER
export is currently loaded - `after` has no promise attached to it that it
was collected AFTER the upgrade, and calling it "op de nieuwe build"
(design 2.1.1's own words, and this tool's description) is only true
when it was. Nothing in this module used to check that: the OLD build,
scanned before the upgrade and never refreshed, would be presented as the
new one and marked `[vastgesteld]` - a false ESTABLISHED fact, the one
thing this product must never produce. `_post_upgrade_freshness_gap()`
below judges `after` against R5's OWN closing row before block 2's
FINDINGS (never its read gaps or `not_assessed` - `cve_check()` still
runs unconditionally, so those two lists are exactly as complete as they
always were) are allowed to stand: no R5 closing row at all (there is no
upgrade to date the export against), an export not proven to postdate
R5's `tijd`, or a build that does not match what R5 itself read live are
all `NIET VASTGESTELD`, each with its own named reason - never a
verdict invented from an export this module cannot date.

BLOCK 3, the extra step, is this module's own reason to exist: a bulletin's
`extraStapNaUpgrade` sentence names a vendor workaround to apply AFTER an
upgrade (design 2.1.1), and whether it has actually been applied is a
fact about the export, not a subordinate clause on the CVE verdict above -
an appliance can be NIET GERAAKT by the CVE itself (build at or above the
fix) while the extra step is still outstanding, or vice versa on an older
build within the bulletin's own affected range. `parse_extra_step()` reads
exactly two things out of that sentence and invents nothing else: the
OBJECT out of `set ns <object>` (-> resource `config/ns<object>`) and the
PARAMETER out of the first `-<naam>` token after that command. No second
table maps a bulletin id to a field name - the knowledge package stays the
only source. Three ways this comes back `NIET VASTGESTELD`, and it is
NEVER `GERAAKT` and NEVER `NIET GERAAKT` on a field this module did not
read:

- the sentence names no recognisable `set ns <object> ... -<parameter>`
  command at all (`EXTRA_STEP_NO_COMMAND`);
- the resource cannot be read from the export at all (a read gap);
- no object under that resource carries the parameter - the honest
  reading of "this build is too old to even carry the field"
  (`EXTRA_STEP_TOO_OLD`).

EVERY TOKEN THIS PARSER RECOGNISES IS BOUNDED ON BOTH SIDES. A pattern without a LEFT boundary read the second
half of any hyphenated Dutch compound as "the parameter": `niet-name` in a
bulletin sentence that names no flag at all became `-name`, a field
virtually every NITRO object carries, and the check reached an ESTABLISHED
`GERAAKT` on a parameter no bulletin ever named - the exact opposite of the
gate this block is. A pattern without a RIGHT boundary silently TRUNCATED
an over-long token into a resource/value the sentence never named. Both
directions now REJECT rather than fabricate: no match is `NIET
VASTGESTELD`, which is a true statement, and a truncated token is not.

BLOCK 4, the anchor and the eight family counts, comes from the LEDGER and
from nothing else - `upgrade.normalised_anchor()` is not re-run here on a
fresh reading of either export. R0's `voormeting_vast` row and R5's closing
row each carry a `configuratie-anker` gate (`upgrade.anchor_evidence_gate`);
R0's ALSO carries a `familietellingen` gate (`upgrade.family_counts_gate`).
This module parses the hex digest and the per-kind counts back OUT of those
gates' own `bewijs` text - the same values `rapport_na_upgrade` would
otherwise have to measure a second time, which is exactly the second
implementation this design forbids.

THREE RULES GOVERN THAT PARSE, and each of them exists because breaking it
produced a verdict on something nobody read:

1. ONLY AN `open` GATE IS A READING. `upgrade_measure` writes
   a deliberately fail-closed `Gate("configuratie-anker", "bewijs", "niet
   beoordeeld", "geen exportpad meegegeven", ...)` precisely so an unread
   anchor is never treated as measured. Reading its `bewijs` anyway (the
   gate is present, so "the gate is there" was true) turned an R0 whose
   export could not be loaded into `gelijk: R0=0, R5=0 [vastgesteld]` on
   every blob kind, one line under an anchor line that said R0 was
   unreadable. `_gate_reading()` now returns a reading ONLY for a gate
   whose own `uitkomst` is `open`, and says per side why not otherwise.
2. ONLY THE CODE-BUILT PART OF AN EVIDENCE STRING IS SEARCHED (important
   2). `family_counts_gate()` appends `; onleesbaar: <familie>: <reden>`,
   and that reason echoes the export manifest's own free-form `status`
   string. A supplied export whose manifest carried `"status": "X
   lbvserver=7"` on some unrelated resource could plant an ESTABLISHED
   count for a family that was never read. The search is therefore
   confined to the segment BEFORE that tail (and, for the anchor gate, to
   the segment after the fixed-shape 64-character digest) - the part
   `upgrade.py` builds out of its own labels and its own integers.
3. ONLY THIS MODULE'S OWN LABELS ARE EXTRACTED. `upgrade.FAMILIES` and the
   three blob kinds from `upgrade._BLOB_PREFIXES`/`_BLOB_MARKER` are
   imported, never retyped, and the digit run is bounded - never a free
   label out of the untrusted ledger text itself.

Missing either row, a gate that is not open, or a digest that will not
parse is `niet vastgesteld` - never `gelijk` - and the reason NAMES THE SIDE: "R5 draagt
geen sluitregel in dit ledger" is actionable, "niet gelezen op R0 en/of R5"
is not.

THE TWO ANCHORS DO NOT COME FROM THE SAME KIND OF READING, and the evidence
says so. R0's `configuratie-anker` is computed
over the EXPORT's `parsed/runningconfig.txt` (`upgrade_measure`, request
`configuratie-anker-export`); R5's over a LIVE `show ns runningConfig` read
over SSH (`scripts/Invoke-GjkUpgradeFase.ps1`, the R5 branch). Those two
texts are not the same text even on a byte-identical configuration: the
collector REDACTS credential-bearing fields on the jumphost before writing
the export (`collect-log.txt`: "geredigeerd op de jumphost"), and not every
redacted line carries one of the three blob markers that
`normalised_anchor()` excludes - measured on
`tests/fixtures/lab-export-vpx-20260826`, three `add vpn sessionAction ...
-ssoCredential <REDACTED>` lines survive the exclusion and go into the
digest. On such an appliance `verschillend` is therefore the permanent
answer, and a difference is NOT by itself configuration drift. Naming both
sources in the evidence, and `ANCHOR_SOURCES_DIFFER` as the reason on a
`verschillend`, is what keeps that honest; `docs/klant/OPENSTAANDE-
METINGEN.md` carries the same statement for the reader who never sees this
file.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.cve import GERAAKT, NIET_GERAAKT, NIET_VASTGESTELD, cve_check, parse_build
from nsmcp.knowledge import Knowledge
from nsmcp.upgrade import (
    _BLOB_MARKER,
    _BLOB_PREFIXES,
    FAMILIES,
    GATE_OUTCOMES,
    _bounded,
    _bounded_run_echo,
    _iso_z,
    _read_moment,
)

# design 2.1.1 - produced verbatim, pinned in tests/test_product_surface.py.
ANCHOR_WORDS: tuple[str, str, str] = ("gelijk", "verschillend", "niet vastgesteld")

# The four sentences of the extra-step table. Every
# one is customer-visible product copy and pinned byte-for-byte in
# tests/test_product_surface.py.
EXTRA_STEP_DONE = "de extra stap is uitgevoerd"
EXTRA_STEP_PENDING = "de extra stap moet nog"
EXTRA_STEP_TOO_OLD = "build te oud, stap nog niet mogelijk"
EXTRA_STEP_NO_COMMAND = "de extra stap noemt geen herkenbaar commando"

# This module's OWN new sentence (the fallback for a
# knowledge package that carries no bulletin with an extra step at all).
# Pinned alongside the four above: "never a silent omission" applies here
# too, not only to block 1. It is a REASON, never an outcome: the outcome
# column of this block is closed to GERAAKT / NIET
# GERAAKT / NIET VASTGESTELD and nothing else.
EXTRA_STEP_NONE_IN_KNOWLEDGE = "geen enkel bulletin in dit kennispakket draagt een extra stap na de upgrade"

# Where each side's anchor came from - customer-visible, pinned, and the
# whole point of naming the source: a `verschillend` caused by the
# SHAPE of the two sources must not be indistinguishable from real drift.
ANCHOR_SOURCE_R0 = "uit de export van voor de upgrade (parsed/runningconfig.txt, geredigeerd verzameld)"
ANCHOR_SOURCE_R5 = "live gelezen na de upgrade (show ns runningConfig over SSH)"
ANCHOR_SOURCES_DIFFER = (
    "de twee ankers komen uit verschillende bronnen: de export van R0 is bij het verzamelen "
    "geredigeerd, de live lezing van R5 niet. Een verschil hoeft daarom geen "
    "configuratiewijziging te zijn; zie docs/klant/OPENSTAANDE-METINGEN.md"
)

# Block 1's honest gap - the per-source coverage of both exports side by
# side needs the comparison engine (`compare.py`) and the retention module
# (`retention.py`) wired in here; both exist on this branch but neither is
# called from this module yet.
BLOCK_ONE_SUBJECT = "per bron voor en na"
BLOCK_ONE_REASON = (
    "de vergelijkingsmotor en de retentiefunctie voor de vorige export zijn nog niet "
    "aan dit gereedschap gekoppeld; zie docs/klant/OPENSTAANDE-METINGEN.md"
)

# Block 2's own subject when it cannot stand
# (the freshness gate below fires) - the same words the tool description
# already uses ("het CVE-oordeel op de nieuwe build"), so the ONE line
# replacing every per-bulletin finding is still recognisable as block 2.
# The three reasons: no R5 closing row at all reuses `_ROW_MISSING["R5"]`
# below (one phrase for "R5 never closed", not two that could drift
# apart); the other two are this gate's own, pinned in
# tests/test_product_surface.py like every other customer-visible
# sentence in this module.
BLOCK_TWO_SUBJECT = "CVE-oordeel op de nieuwe build"
FRESHNESS_EXPORT_OUDER_TEXT = "export ouder dan de upgrade"
FRESHNESS_BUILD_AFWIJKEND_TEXT = "de build in de export komt niet overeen met de build die R5 na de upgrade live las"

# The three kinds of excluded blob line `upgrade.normalised_anchor()`
# counts - imported, not retyped, so this module's rendering can never name
# a kind that function itself does not recognise.
_BLOB_KINDS: tuple[str, ...] = (*_BLOB_PREFIXES, _BLOB_MARKER)

# The two ledger events this module reads the anchor/family evidence off
# of - R0's OWN closing event (never just "the last R0 row", which could be
# a still-open or a failed R0), and every event that genuinely CLOSES R5.
_R0_ANCHOR_EVENT = "voormeting_vast"
_R5_CLOSING_EVENTS = ("fase_geslaagd", "fase_mislukt", "poort_dicht")

_ANCHOR_GATE = "configuratie-anker"
_FAMILY_GATE = "familietellingen"
# The gate R5's own branch writes with the LIVE build it read right
# after the reboot (`Invoke-GjkUpgradeFase.ps1`, the R5 branch) - the same
# `_gate_reading()` discipline as the two gates above applies: its `bewijs`
# is read only when its OWN `uitkomst` is `open`, never otherwise.
_DOELBUILD_GATE = "doelbuild bereikt"

# How each phase's own row is named when it is missing or does not carry
# the gate - the reason has to say WHICH SIDE.
_ROW_LABEL: dict[str, str] = {
    "R0": "de voormeting_vast-regel van R0",
    "R5": "de sluitregel van R5",
}
_ROW_MISSING: dict[str, str] = {
    "R0": "R0 draagt geen voormeting_vast-regel in dit ledger",
    "R5": "R5 draagt geen sluitregel in dit ledger",
}

# `_gate_reading()`'s own bound, distinct from
# `_bounded_run_echo()`'s DEFAULT (`_UNTRUSTED_ECHO_LIMIT`, 200) - a
# display-safe cap, never a parse-safe one, and this seam feeds a parser.
# Comfortably above every legitimate `configuratie-anker`/
# `familietellingen`/`doelbuild bereikt` bewijs (measured: 129-207
# characters), so real input is unaffected; still a real, bounded limit,
# never unbounded. See `_gate_reading()`'s own docstring for the measured
# defect this closes.
_GATE_BEWIJS_LIMIT = 4000

# The literal head/tail markers `upgrade.anchor_evidence_gate()` and
# `upgrade.family_counts_gate()` write around the part of their evidence
# that this module may search. Everything after `_UNTRUSTED_TAIL` is an
# echo of an export read gap and therefore untrusted content.
_FAMILY_HEAD = "familietellingen: "
_UNTRUSTED_TAIL = "; onleesbaar:"

# Bounded repetition on every token `parse_extra_step()` pulls out of a
# knowledge sentence: NITRO object/field names are always short, so this
# changes nothing for legitimate input, and it keeps a hostile sentence
# from turning into an unbounded echo (hardening: knowledge is untrusted,
# same as export/config/ledger).
_TOKEN_LIMIT = 64
_VALUE_LIMIT = 80

# `(?<![\w-])` - the LEFT boundary that makes these tokens, and not the
# tail of a hyphenated word, the thing being matched. `(?![A-Za-z0-9])` /
# `(?![^\s`])` - the RIGHT boundary that makes an over-long token FAIL to
# match instead of being silently cut down to the bound. See the module
# docstring: reject, never fabricate.
_SET_NS_RE = re.compile(
    rf"(?<![\w-])set\s+ns\s+([A-Za-z][A-Za-z0-9]{{0,{_TOKEN_LIMIT - 1}}})(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_FLAG_VALUE_RE = re.compile(
    rf"(?<![\w-])-([A-Za-z][A-Za-z0-9]{{0,{_TOKEN_LIMIT - 1}}})\s+([^\s`]{{1,{_VALUE_LIMIT}}})(?![^\s`])"
)

# `(?![0-9a-fA-F])` - the RIGHT boundary. Without it
# a ledger line carrying `anker=<128 hex>` still matched - on the FIRST 64
# of them, silently - and `_blob_segment()`/`_family_segment()` then
# searched the 64 LEFTOVER hex characters (never a real evidence segment)
# for known labels, found none, and every blob/family count compared 0 to
# 0 as `gelijk` [vastgesteld] on a digest this parser never read in full.
# Two DIFFERENT 128-character digests sharing only their first 64
# characters read as the SAME anchor for the same reason. An over-long
# digest is now NO MATCH at all - `niet vastgesteld`, the same "reject,
# never fabricate" rule the module docstring already states for the other
# two patterns in this file.
_ANCHOR_HASH_RE = re.compile(r"anker=([0-9a-fA-F]{64})(?![0-9a-fA-F])")


def parse_extra_step(sentence) -> tuple[str, str, str] | None:
    """`(resource, parameter, value)` out of a knowledge-carried
    `extraStapNaUpgrade` sentence, or `None` when it names no recognisable
    `set ns <object> ... -<parameter> <waarde>` command.

    The OBJECT is the token right after `set ns` (`httpProfile` in
    `set ns httpProfile <profiel> -http2SmallWndTimeout 30`) -> resource
    `config/ns<object.lower()>`
    (`config/nshttpprofile`) - the same file-naming rule `Export.objects()`
    already applies to every other resource (`export.py`:
    `resource.split("/")[-1]`). The PARAMETER is the first `-<naam>` token
    AFTER that command, lower-cased to match NITRO's own (lower-case)
    field-naming convention - the vendor CLI flag is `-http2SmallWndTimeout`,
    the JSON attribute this product's exports carry is
    `http2smallwndtimeout`. The VALUE is the token right after the flag,
    with a trailing backtick or sentence punctuation stripped (the sentence
    itself is written inside backticks, "... 30\\` zetten").

    A token that does not fit inside its bound, or a `-<naam>` that is
    really the second half of a hyphenated word, is NO MATCH - `None`, and
    therefore `NIET VASTGESTELD` at the caller. See the module docstring
    for the two verdicts that produced this rule.
    """
    text = str(sentence or "")
    command = _SET_NS_RE.search(text)
    if command is None:
        return None
    flag = _FLAG_VALUE_RE.search(text, command.end())
    if flag is None:
        return None
    resource = f"config/ns{command.group(1).lower()}"
    parameter = flag.group(1).lower()
    value = flag.group(2).rstrip("`.,;)")
    if not value:
        return None
    return resource, parameter, value


def _bulletin_id(bulletin: dict) -> str:
    return _bounded(str(bulletin.get("bulletin") or "(onbekend bulletin)"), 60)


def _extra_step_finding(after, bulletin: dict) -> Finding:
    subject = f"extra stap na de upgrade ({_bulletin_id(bulletin)})"
    sentence = bulletin.get("extraStapNaUpgrade")
    parsed = parse_extra_step(sentence if isinstance(sentence, str) else "")
    if parsed is None:
        return Finding(
            subject=subject,
            outcome=NIET_VASTGESTELD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="de zin uit het kennispakket noemt geen `set ns <object> ... -<parameter>`",
            reason=EXTRA_STEP_NO_COMMAND,
            subject_is_name=False,
        )
    resource, parameter, expected = parsed
    rows, gap = after.objects(resource)
    if gap is not None:
        return Finding(
            subject=subject,
            outcome=NIET_VASTGESTELD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=f"{resource} niet leesbaar in de export: {_bounded(gap.reason)}",
            reason=EXTRA_STEP_TOO_OLD,
            subject_is_name=False,
        )
    dragend = [r for r in rows if isinstance(r, dict) and parameter in r]
    if not dragend:
        return Finding(
            subject=subject,
            outcome=NIET_VASTGESTELD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=f"{resource}: geen object draagt het veld {parameter}",
            reason=EXTRA_STEP_TOO_OLD,
            subject_is_name=False,
        )
    # Case-INSENSITIVE. The vendor writes its own
    # casing in the bulletin sentence (`ENABLED`) and NITRO returns its own
    # in the export (`enabled`); those are the same value, and comparing
    # them byte-for-byte turned a step that HAD been carried out into
    # `GERAAKT`. The evidence still echoes the sentence's own spelling.
    verwacht = expected.casefold()
    afwijkend = [r for r in dragend if str(r.get(parameter)).strip().casefold() != verwacht]
    if afwijkend:
        return Finding(
            subject=subject,
            outcome=GERAAKT,
            certainty=Certainty.ESTABLISHED,
            evidence=(
                f"{resource}: {len(afwijkend)} van {len(dragend)} object(en) dragen "
                f"{parameter} niet met de verwachte waarde {expected}"
            ),
            reason=EXTRA_STEP_PENDING,
            subject_is_name=False,
        )
    return Finding(
        subject=subject,
        outcome=NIET_GERAAKT,
        certainty=Certainty.ESTABLISHED,
        evidence=f"{resource}: {len(dragend)} object(en) dragen {parameter}={expected}",
        reason=EXTRA_STEP_DONE,
        subject_is_name=False,
    )


def _block_extra_step(after, knowledge: Knowledge) -> list[Finding]:
    if knowledge.missing:
        reason = knowledge.reason.strip() or "het kennispakket kon niet geladen worden"
        return [
            Finding(
                subject="extra stap na de upgrade",
                outcome=NIET_VASTGESTELD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"kennispakket: {reason}",
                reason=reason,
                subject_is_name=False,
            )
        ]
    bulletins = [b for b in knowledge.cve if isinstance(b, dict) and str(b.get("extraStapNaUpgrade") or "").strip()]
    if not bulletins:
        return [
            Finding(
                subject="extra stap na de upgrade",
                outcome=NIET_VASTGESTELD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=(
                    f"kennispakket geladen, {len(knowledge.cve)} bulletin(s), geen daarvan draagt extraStapNaUpgrade"
                ),
                reason=EXTRA_STEP_NONE_IN_KNOWLEDGE,
                subject_is_name=False,
            )
        ]
    findings = [_extra_step_finding(after, bulletin) for bulletin in bulletins]
    if knowledge.unpinned_reason:
        # The step, its parameter and its value all come out of a package
        # the configuration does not pin: whoever can write the knowledge
        # path can make an outstanding step read as done. The outcome stays
        # visible; that it holds is not established.
        findings = [
            replace(finding, certainty=Certainty.NOT_ESTABLISHED, reason=knowledge.unpinned_reason)
            if finding.certainty is Certainty.ESTABLISHED
            else finding
            for finding in findings
        ]
    return findings


def _closing_row(lines, phase: str, events: tuple[str, ...]) -> dict | None:
    """The LAST row in `lines` for `phase` whose `gebeurtenis` is one of
    `events` - never merely "the last row for this phase", which could be a
    still-open `fase_gestart` or a `fase_mislukt` when `events` asks for
    R0's own closing event specifically."""
    row = None
    for regel in lines:
        if isinstance(regel, dict) and regel.get("fase") == phase and regel.get("gebeurtenis") in events:
            row = regel
    return row


def _gate_reading(row: dict | None, fase: str, naam: str) -> tuple[str | None, str]:
    """`(bewijs, reden)` for gate `naam` on `row`.

    `bewijs` is a string ONLY when the row exists, carries that gate, AND
    that gate's own `uitkomst` is `open`. Anything else is `(None, reden)`
    with a reason that names the side and what is wrong with it - see rule
    1 in the module docstring: a `niet beoordeeld` gate is the product
    saying "not measured", and reading its evidence anyway is how an unread
    R0 came back as `gelijk ... [vastgesteld]`.

    The gate's own outcome is echoed only when it is one of this product's
    three gate words (`upgrade.GATE_OUTCOMES`, imported); anything else out
    of the untrusted ledger becomes `onbekend` rather than free text in
    product copy.

    This is the ONE seam where every caller in this
    module gets ledger bewijs - `_anchor_hash()`/`_known_counts()`/
    `cve.parse_build()` only ever pull a known, bounded pattern back OUT of
    it, which already kept a hostile payload from reaching an answer, but
    that safety lived entirely in HOW those callers happen to read it, not
    in this seam itself. `_bounded_run_echo()` (upgrade.py) - the same
    rendergrens `stand_answer()` already applies to every poort bewijs - is
    applied HERE instead, so a future caller of this function inherits it
    too, instead of having to remember to re-apply it.

    `_bounded_run_echo()`'s OWN docstring on this
    file's `_render_or()` sibling already says it - "never use for
    parsing" - and this seam feeds a parser (`_anchor_hash()`/
    `_known_counts()`) right below. The DEFAULT bound
    (`_UNTRUSTED_ECHO_LIMIT`, 200) is a display cap, not a parse-safe one:
    a truncated digit run is still a well-formed `key=\\d+` match, so a
    count cut in half read as a SHORTER, coincidentally-equal number on
    both sides - demonstrated with R0 `lbmonitor=1000000007` and R5
    `lbmonitor=1000000009` both truncating to `lbmonitor=100`, a false
    `gelijk [vastgesteld]`. `_GATE_BEWIJS_LIMIT` below is scrubbing-only in
    practice for this seam (control characters and line breaks still
    collapse, exactly as before) - it is comfortably above every
    legitimate `configuratie-anker`/`familietellingen`/`doelbuild bereikt`
    bewijs this product's own writers ever build (measured: 129-207
    characters across the lab fixtures and the tests below; bounded at the
    OTHER end by `_known_counts()`'s own 15-digit ceiling per count), so it
    changes nothing for real input and only removes the PARSE-relevant
    truncation risk.
    """
    if row is None:
        return None, _ROW_MISSING[fase]
    for poort in row.get("poort") or []:
        if isinstance(poort, dict) and poort.get("naam") == naam:
            uitkomst = str(poort.get("uitkomst") or "")
            if uitkomst != "open":
                woord = uitkomst if uitkomst in GATE_OUTCOMES else "onbekend"
                return None, f"de {naam}-poort van {fase} staat op {woord}, niet op open"
            return _bounded_run_echo(str(poort.get("bewijs") or ""), _GATE_BEWIJS_LIMIT), ""
    return None, f"{_ROW_LABEL[fase]} draagt geen {naam}-poort"


def _anchor_hash(bewijs: str | None) -> str | None:
    if bewijs is None:
        return None
    match = _ANCHOR_HASH_RE.search(bewijs)
    return match.group(1).lower() if match else None


def _blob_segment(bewijs: str | None) -> str | None:
    """The part of a `configuratie-anker` gate's evidence that
    `anchor_evidence_gate()` builds out of its OWN labels and integers:
    everything after the fixed-shape 64-character digest. No digest, no
    segment - and therefore no counts (rule 2, module docstring)."""
    if bewijs is None:
        return None
    match = _ANCHOR_HASH_RE.search(bewijs)
    return bewijs[match.end() :] if match else None


def _family_segment(bewijs: str | None) -> str | None:
    """The part of a `familietellingen` gate's evidence that
    `family_counts_gate()` builds out of its OWN labels and integers:
    after the `familietellingen: ` head and BEFORE the `; onleesbaar: `
    tail, which echoes an export read gap - untrusted content that could
    otherwise plant a count for a family nobody read (rule 2)."""
    if bewijs is None:
        return None
    _, teken, rest = bewijs.partition(_FAMILY_HEAD)
    if not teken:
        return None
    return rest.split(_UNTRUSTED_TAIL)[0]


def _known_counts(segment: str | None, keys: tuple[str, ...]) -> dict[str, int] | None:
    """`{key: aantal}` for every KNOWN key (`keys`) present in `segment`, or
    `None` when there is no trustworthy segment at all. A key from `keys`
    simply absent from the text is not an error - the caller tells a
    genuine zero (blob kinds, which `anchor_evidence_gate()` only lists when
    it counted one) from "not read" (families) by looking the key up in the
    returned dict.

    Only ever extracts a KNOWN, code-side label followed by `=<digits>`,
    with a LEFT boundary so `csvserver=1` is never read as `vserver=1`, and
    a BOUNDED digit run (15 digits: no real count is remotely close) so a
    hostile ledger line cannot reach Python's own int-string conversion
    ceiling (`sys.set_int_max_str_digits`, 4300 by default) - unbounded
    `\\d+` on untrusted content turned a single oversized ledger row into an
    uncaught `ValueError` here."""
    if segment is None:
        return None
    gevonden: dict[str, int] = {}
    for key in keys:
        match = re.search(rf"(?<![\w-]){re.escape(key)}=(\d{{1,15}})", segment)
        if match is not None:
            gevonden[key] = int(match.group(1))
    return gevonden


def _count_finding(*, subject: str, waarde0: int | None, reden0: str, waarde1: int | None, reden1: str) -> Finding:
    """One count line. `niet vastgesteld` names the SIDE that is missing and
    why - the anchor line has done that since the first version, and eleven
    count lines sharing one generic "niet gelezen op R0 en/of R5" told a
    reader nothing about which half of the run to go and look at."""
    if waarde0 is None or waarde1 is None:
        stukken = [reden for waarde, reden in ((waarde0, reden0), (waarde1, reden1)) if waarde is None and reden]
        reden = "; ".join(stukken) or "niet gelezen op R0 en/of R5"
        return Finding(
            subject=subject,
            outcome=ANCHOR_WORDS[2],
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=reden,
            reason=reden,
            subject_is_name=False,
        )
    woord = ANCHOR_WORDS[0] if waarde0 == waarde1 else ANCHOR_WORDS[1]
    return Finding(
        subject=subject,
        outcome=f"{woord}: R0={waarde0}, R5={waarde1}",
        certainty=Certainty.ESTABLISHED,
        evidence=f"R0={waarde0}, R5={waarde1}",
        subject_is_name=False,
    )


def _ledger_age_finding(ledger_lines, now: datetime) -> Finding:
    """The age of the newest ledger row - block 4 is derived from the
    ledger and from nothing else, so how old that ledger is belongs in the
    answer. The same statement, in the same words, as
    `upgrade.stand_answer()` makes."""
    laatste = None
    heeft_regels = False
    for regel in ledger_lines:
        heeft_regels = True
        moment = _read_moment(regel.get("tijd")) if isinstance(regel, dict) else None
        if moment is not None and (laatste is None or moment > laatste):
            laatste = moment
    if laatste is None:
        reden = (
            "geen ledgerregel met een leesbare tijd"
            if heeft_regels
            else "het ledger draagt geen regels voor deze run/dit doel"
        )
        return Finding(
            subject="laatste ledgerregel",
            outcome=ANCHOR_WORDS[2],
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=reden,
            reason=reden,
            subject_is_name=False,
        )
    ouderdom_dagen = (now - laatste).total_seconds() / 86400
    return Finding(
        subject="laatste ledgerregel",
        outcome=f"{ouderdom_dagen:.1f} dag(en) oud",
        certainty=Certainty.ESTABLISHED,
        evidence=f"tijd van de laatste ledgerregel: {_iso_z(laatste)}",
        subject_is_name=False,
    )


def _block_anchor(ledger_lines, now: datetime) -> list[Finding]:
    r0 = _closing_row(ledger_lines, "R0", (_R0_ANCHOR_EVENT,))
    r5 = _closing_row(ledger_lines, "R5", _R5_CLOSING_EVENTS)

    anker_bewijs0, anker_reden0 = _gate_reading(r0, "R0", _ANCHOR_GATE)
    anker_bewijs1, anker_reden1 = _gate_reading(r5, "R5", _ANCHOR_GATE)
    familie_bewijs0, familie_reden0 = _gate_reading(r0, "R0", _FAMILY_GATE)
    familie_bewijs1, familie_reden1 = _gate_reading(r5, "R5", _FAMILY_GATE)

    anker0 = _anchor_hash(anker_bewijs0)
    anker1 = _anchor_hash(anker_bewijs1)
    if anker_bewijs0 is not None and anker0 is None:
        anker_reden0 = "het configuratie-anker-bewijs van R0 is niet leesbaar"
    if anker_bewijs1 is not None and anker1 is None:
        anker_reden1 = "het configuratie-anker-bewijs van R5 is niet leesbaar"

    blobs0 = _known_counts(_blob_segment(anker_bewijs0), _BLOB_KINDS)
    blobs1 = _known_counts(_blob_segment(anker_bewijs1), _BLOB_KINDS)
    fams0 = _known_counts(_family_segment(familie_bewijs0), FAMILIES)
    fams1 = _known_counts(_family_segment(familie_bewijs1), FAMILIES)
    if familie_bewijs0 is not None and fams0 is None:
        familie_reden0 = "het familietellingen-bewijs van R0 is niet leesbaar"
    if familie_bewijs1 is not None and fams1 is None:
        familie_reden1 = "het familietellingen-bewijs van R5 is niet leesbaar"

    findings: list[Finding] = []
    if anker0 is None or anker1 is None:
        stukken = [
            reden for anker, reden in ((anker0, anker_reden0), (anker1, anker_reden1)) if anker is None and reden
        ]
        reden = "; ".join(stukken) or "het anker is niet vast te stellen"
        findings.append(
            Finding(
                subject=_ANCHOR_GATE,
                outcome=ANCHOR_WORDS[2],
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=reden,
                reason=reden,
                subject_is_name=False,
            )
        )
    else:
        gelijk = anker0 == anker1 and (blobs0 or {}) == (blobs1 or {})
        findings.append(
            Finding(
                subject=_ANCHOR_GATE,
                outcome=ANCHOR_WORDS[0] if gelijk else ANCHOR_WORDS[1],
                certainty=Certainty.ESTABLISHED,
                evidence=(f"R0: anker={anker0} ({ANCHOR_SOURCE_R0}); R5: anker={anker1} ({ANCHOR_SOURCE_R5})"),
                reason="" if gelijk else ANCHOR_SOURCES_DIFFER,
                subject_is_name=False,
            )
        )

    for soort in _BLOB_KINDS:
        findings.append(
            _count_finding(
                subject=f"uitgesloten blob-regels: {soort}",
                waarde0=None if blobs0 is None else blobs0.get(soort, 0),
                reden0=anker_reden0,
                waarde1=None if blobs1 is None else blobs1.get(soort, 0),
                reden1=anker_reden1,
            )
        )
    for familie in FAMILIES:
        ontbreekt0 = familie_reden0 if fams0 is None else f"de {_FAMILY_GATE}-poort van R0 noemt {familie} niet"
        ontbreekt1 = familie_reden1 if fams1 is None else f"de {_FAMILY_GATE}-poort van R5 noemt {familie} niet"
        findings.append(
            _count_finding(
                subject=f"familietelling: {familie}",
                waarde0=None if fams0 is None else fams0.get(familie),
                reden0=ontbreekt0,
                waarde1=None if fams1 is None else fams1.get(familie),
                reden1=ontbreekt1,
            )
        )
    findings.append(_ledger_age_finding(ledger_lines, now))
    return findings


def _post_upgrade_freshness_gap(r5: dict | None, after) -> str | None:
    """`None` when `after` may be judged as the post-upgrade export block 2
    claims it is; otherwise the reason it may not.

    Three independent ways this comes back non-`None`, checked in order,
    and NEVER a verdict invented from an export this function cannot date:

    1. R5 never closed in this ledger at all - there is no upgrade to date
       the export against. Reuses `_ROW_MISSING["R5"]` (rule: one phrase
       for "R5 never closed", not two that could drift apart - the anchor
       block above already says exactly this for the same row).
    2. R5 closed, but `after.collected_at` does not read as a moment
       STRICTLY AFTER R5's own `tijd` - an unreadable timestamp on either
       side is treated the same as "not proven newer": `FRESHNESS_EXPORT_
       OUDER_TEXT`, verbatim per the finding.
    3. The export postdates R5, but its OWN build (`config/nsversion`)
       does not match the build R5 itself read LIVE right after the
       reboot (the `doelbuild bereikt` gate, read only when that gate's
       own `uitkomst` is `open` - `_gate_reading()`, the same rule the
       anchor/family gates already follow). Neither side's text is ever
       echoed raw; `parse_build()` compares the PARSED branch/build pair
       only, the same restraint `build_echo()` applies for display.
    """
    if r5 is None:
        return _ROW_MISSING["R5"]
    r5_moment = _read_moment(r5.get("tijd"))
    export_moment = _read_moment(getattr(after, "collected_at", None))
    if r5_moment is None or export_moment is None or export_moment <= r5_moment:
        return FRESHNESS_EXPORT_OUDER_TEXT
    r5_bewijs, _reden = _gate_reading(r5, "R5", _DOELBUILD_GATE)
    r5_build = parse_build(r5_bewijs) if r5_bewijs is not None else None
    row, _gap = after.single("config/nsversion")
    export_build = parse_build(row.get("version")) if isinstance(row, dict) else None
    if r5_build is None or export_build is None or r5_build != export_build:
        return FRESHNESS_BUILD_AFWIJKEND_TEXT
    return None


def report_after_upgrade(before, after, knowledge: Knowledge, ledger_lines, *, now: datetime | None = None) -> Answer:
    """The before/after upgrade report - blocks 2, 3 and 4 only (see the
    module docstring for why block 1 is a `NotAssessed`, not a finding).

    `before` is accepted (and otherwise unused) so this function's
    signature already matches what wiring in block 1 needs: `compare.
    compare_answer(before, after, knowledge, mode)` is the natural block-1
    caller once it is wired in. `after` is the CURRENT/new export - block 2 and block 3 both
    judge it, never `before`. `ledger_lines` is already scoped to one
    run/target by the caller (the same convention `upgrade.stand_answer()`
    uses) - this function does not filter on `run` or `doel` itself. `now`
    exists for the ledger-age statement and for the tests that pin it;
    absent, it is the current UTC moment.
    """
    del before  # block 1 is not wired in here - see module docstring.

    # `cve_check()` runs UNCONDITIONALLY - its `read_gaps` and
    # `not_assessed` travel exactly as they always did, freshness or not
    # ("all three lists travel" is not narrowed
    # by the freshness gate). Only its FINDINGS are gated: replaced with ONE
    # NIET VASTGESTELD line, naming the reason, when `after` is not proven
    # to be the post-upgrade export - never silently kept, and never
    # invented from data this function cannot date.
    cve_answer = cve_check(after, knowledge)
    r5 = _closing_row(ledger_lines, "R5", _R5_CLOSING_EVENTS)
    freshness_gap = _post_upgrade_freshness_gap(r5, after)
    if freshness_gap is not None:
        findings: list[Finding] = [
            Finding(
                subject=BLOCK_TWO_SUBJECT,
                outcome=NIET_VASTGESTELD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=freshness_gap,
                reason=freshness_gap,
                subject_is_name=False,
            )
        ]
    else:
        findings = list(cve_answer.findings)
    read_gaps: list[ReadGap] = list(cve_answer.read_gaps)

    findings.extend(_block_extra_step(after, knowledge))
    findings.extend(_block_anchor(ledger_lines, now or datetime.now(UTC)))

    return Answer(
        question="stand van voor en na de upgrade",
        findings=findings,
        read_gaps=read_gaps,
        # Block 2's OWN not-assessed entries travel with block 2;
        # this module's block-1 entry is appended, never substituted.
        not_assessed=[
            *cve_answer.not_assessed,
            NotAssessed(subject=BLOCK_ONE_SUBJECT, reason=BLOCK_ONE_REASON),
        ],
        knowledge_age_days=cve_answer.knowledge_age_days,
        knowledge_date=cve_answer.knowledge_date,
    )
