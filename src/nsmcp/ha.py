"""May I change this on the primary, or does HA need attention first?

FOUR statements, side by side, and one vocabulary. The design (2.2 row A4)
writes it out: `rolverdeling` / `sync en propagatie` / `geforceerde stand` /
`config-drift`, "elk aan-uit-onbevestigd". So the four are DIMENSIONS - what
this answer looks at - and `aan` / `uit` / `onbevestigd` is the ONE set of
state words they speak in, lower case, in a running Dutch sentence.

Each word says whether THE THING NAMED IS THE CASE, never whether it is good
news; the polarity therefore differs per dimension, and that is the point:

| dimension          | `aan` means                       | safe when |
|--------------------|-----------------------------------|-----------|
| rolverdeling       | there is a 1-Primary distribution | `aan`     |
| sync en propagatie | propagation and sync are in effect| `aan`     |
| geforceerde stand  | a node is forced (STAY...)        | `uit`     |
| config-drift       | running and saved differ          | `uit`     |

That table is not only here: every dimension's EVIDENCE says whether that
dimension holds up the change, so a reader of the answer never has to know
this file to read a line correctly. On the real standalone export that
reads `niet van toepassing / niet van toepassing / uit / uit` (the drift
there was only the header lines and the closing `Done`, which
`config_drift.py` leaves out). Same statement, no extra word - see
`HaDimension.to_finding`.

`onbevestigd` is the third word of the vocabulary and the only one that is
NOT established: it is the "niet"-word of this tool, exactly as the design's
2.1.1 prescribes for a read gap ("een leesgat heeft geen eigen woord").

WHAT IS DELIBERATELY NOT A STATE WORD HERE. `onbekend` and
`niet van toepassing` both stand in the 2.1.1 table (the applicability row,
A12). Design 2.1 forbids a tool-specific STATE word that overlaps in meaning
with a word from that table, so neither is one: `STATE_WORDS` stays the
three words above. `niet van toepassing` is nonetheless what a dimension
SAYS on a standalone appliance - in the applicability position, which is
the position NSHC uses it in too, and outside `STATE_WORDS` so the two
cannot be confused (see `_STANDALONE` below for the measurement, and
`OUTCOME_WORDS` for the vocabulary a dimension line is validated against).

THE MIRROR. NSHC's four HA controls
(`backend/readonly/Invoke-NshcSecurityScorecard.ps1:2542-2545`) are these four
dimensions, one for one, and the branches below mirror `Get-NshcHaVerdict`
(same file, :648-742) control by control:

| NSHC control                       | here                 |
|------------------------------------|----------------------|
| GJK-L1-HA-001 rolverdeling         | `rolverdeling`       |
| GJK-L1-HA-002 propagatie en sync   | `sync en propagatie` |
| GJK-L1-HA-003 geen geforceerde state | `geforceerde stand`|
| GJK-L1-HA-004 running-vs-saved     | `config-drift`       |

The config-drift half is the one place this product says MORE than NSHC, and
knowingly: NSHC calls that control "read-only via NITRO niet hard bewijsbaar"
(same file, :737-739) and always reports it unassessed, while THIS export
carries `parsed/runningconfig.txt` and `parsed/savedconfig.txt` with a hash
each (design 2.2 row A4 names both as sources). It reports COUNTS and never a
config line: a running-config line can carry a credential (design 3.6, unit
8). The one tool that shows the lines themselves is `config_drift`, only at
openheid `volledig` and never a line with a secret - see the fences in
`config_drift.py`, which also owns the comparison both tools share.

What this answer never claims, and says so out loud:
- that a failover works. That needs a failover test, not a configuration read.
- that the partner carries the same configuration. That needs a second scan
  (`rapport_vergelijk`, mode HA-parity).
"""

from __future__ import annotations

from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap, repeatable_token
from nsmcp.config_drift import comparison_evidence, read_comparison, undecided_reason
from nsmcp.export import MISSING as _MISSING, RUNNING_CONFIG_FILE, SAVED_CONFIG_FILE, shape_or_missing_at
from nsmcp.knowledge import Knowledge
from nsmcp.overzicht import HA_STATES

RESOURCE = "config/hanode"

QUESTION = "mag ik hier op de primary wijzigen"

# The four dimensions of design 2.2 row A4, in reporting order.
ROLES_LABEL = "rolverdeling"
SYNC_LABEL = "sync en propagatie"
FORCED_LABEL = "geforceerde stand"
DRIFT_LABEL = "config-drift"
LABELS = (ROLES_LABEL, SYNC_LABEL, FORCED_LABEL, DRIFT_LABEL)

# The ONE state vocabulary of this tool. Lower case, sentence words.
ON = "aan"
OFF = "uit"
UNCONFIRMED = "onbevestigd"
STATE_WORDS = (ON, OFF, UNCONFIRMED)

# NOT a fourth STATE word, deliberately. This is the applicability word of
# the design's 2.1.1 table, in the APPLICABILITY position - the slot NSHC
# fills with `Applicability='NotApplicable'`. The design forbids a
# tool-specific STATE word that overlaps a word of that table; it does not
# forbid saying, in that table's own word, that a control does not apply
# here. Keeping it OUT of `STATE_WORDS` is what makes that difference
# machine-checkable instead of a matter of intent.
NOT_APPLICABLE = "niet van toepassing"
# What a dimension line may say: the three state words plus the one
# applicability word. `HaDimension.__post_init__` validates against this.
OUTCOME_WORDS = STATE_WORDS + (NOT_APPLICABLE,)

# The four NSHC controls these four dimensions mirror, one for one - as a
# MACHINE-READABLE mapping, not only as the docstring table above.
# An earlier measurement found that table to be an unmeasured claim: the ids
# lived in docstrings, the answer printed neither an id nor a severity,
# and the parity gate covered everything EXCEPT these four - so "equal to
# NSHC in id, severity and word" was a sentence no test could fail.
# The severities are NSHC's own, read from every branch of
# `Get-NshcHaVerdict` (constant per control across all of them, asserted
# by the extractor). The keys are `hidden_rules.SEVERITY_WORDS` keys, so
# this product keeps ONE severity vocabulary rather than growing a second;
# tests/test_parity_nshc.py compares all three axes against the vendored
# readout.
HA_CONTROLS = {
    ROLES_LABEL: ("GJK-L1-HA-001", "high"),
    SYNC_LABEL: ("GJK-L1-HA-002", "medium"),
    FORCED_LABEL: ("GJK-L1-HA-003", "high"),
    DRIFT_LABEL: ("GJK-L1-HA-004", "medium"),
}

# THE STANDALONE APPLIANCE, MEASURED IN NSHC (2026-09-06).
# `Get-NshcHaVerdict` (Invoke-NshcSecurityScorecard.ps1:666, :705, :731) gives
# GJK-L1-HA-001/002/003 the status `niet-beoordeelbaar` with `naReason='scope'`
# on a readable source of 0 or 1 node, and :826 maps that naReason to
# `Status='NOT_ASSESSED'; Severity='None'; Confidence='None';
# Applicability='NotApplicable'`. Three things follow, and all three are
# honoured here:
#   1. It is NOT a failure. So never a word that reads as a defect to repair.
#   2. It is NOT a read gap either - NSHC's own word for that is
#      `naReason='readgap'`, and it deliberately uses a different one here.
#      So `onbevestigd` would be untrue: nothing failed to be read.
#   3. It carries NO risk weight, and the evidence says plainly what it is
#      ("Standalone appliance: N HA-node(s) gelezen, geen HA-paar").
# This used to be said with `uit`, and that was the one
# thing those three points do NOT support: `uit` is a STATE, and it
# confirms a role distribution that does not exist on a single appliance.
# `uit [vastgesteld]` therefore established something nobody measured. The
# word is now `NOT_APPLICABLE`, which is what NSHC says in its own
# vocabulary, and it is ESTABLISHED - because `config/hanode` really WAS
# read usably, and what that read establishes is that the control does not
# apply here, not what its state is. It is not a read gap either (point 2),
# so `onbevestigd` stays wrong. And per point 3 it holds up nothing: a
# role distribution that does not exist cannot block a change, and saying
# it does would be a risk this read did not find. The evidence still
# carries the standalone statement itself.
_STANDALONE = "geen HA-paar in deze export"

# The `hastatus` values NSHC calls healthy - case-insensitive EXACT match
# (Invoke-NshcSecurityScorecard.ps1:727, NshcHaTruth.ps1:177). Anything else -
# UNKNOWN, DOWN, empty - counts as not-up and is therefore never a `uit` on
# the forced dimension, only an `onbevestigd`.
HEALTHY_HASTATUS = ("UP", "ENABLE", "ENABLED")
# The forced states, matched as a SUBSTRING and case-insensitively, exactly as
# NSHC matches them (`-match '(?i)STAYSECONDARY|STAYPRIMARY'`, :726).
FORCED_HASTATUS = ("STAYPRIMARY", "STAYSECONDARY")

ENABLED = "ENABLED"
DISABLED = "DISABLED"
# The two roles a healthy pair carries. Both are members of `HA_STATES`, the
# closed role vocabulary this product already measured for the SAME field in
# `overzicht.py` - imported rather than copied, because a second list of the
# same vocabulary is a second place for it to drift. Pinned by a test.
PRIMARY = "Primary"
SECONDARY = "Secondary"
# THE CLOSED `hasynchronizationstatus` VOCABULARY, MEASURED IN NSHC.
# `Invoke-NshcSecurityScorecard.ps1:681` and `NshcHaTruth.ps1:191` only look
# for `FAIL|IN PROGRESS`, and everything else silently passes there. NSHC's
# DEEP sync truth does close the vocabulary, and this is that closed set,
# copied from the three regexes at `NshcHaDriftTruth.ps1:52-54`:
#
#   healthy  ^\s*(SUCCESS|ENABLED|ENABLE|UP TO DATE|UPTODATE|IN SYNC|INSYNC
#                 |COMPLETE|COMPLETED|DONE|OK)\s*$     - anchored, whole value
#   fail     (FAIL|OUT OF SYNC|OUTOFSYNC|ERROR|DISABLED|MISMATCH|DIVERGE)
#   progress (IN PROGRESS|PROGRESS|SYNCING|PENDING|PARTIAL)
#
# The last two are SUBSTRINGS, the first is the WHOLE value, exactly as NSHC
# matches them - so "PARTIAL FAIL" is a failure (fail is tested first) and
# "PENDING" is a running sync, not a value to shrug at. Anything outside all
# three is a value this version does not know, and NSHC says out loud what
# must happen then (`NshcHaDriftTruth.ps1:80`, and the report line at
# `New-NshcHaDriftReport.ps1:154`): "een onbekende sync-status valt fail-closed
# naar 'onbevestigd' (nooit een valse 'in sync')".
_SYNC_FAILED = ("FAIL", "OUT OF SYNC", "OUTOFSYNC", "ERROR", "DISABLED", "MISMATCH", "DIVERGE")
_SYNC_RUNNING = ("IN PROGRESS", "PROGRESS", "SYNCING", "PENDING", "PARTIAL")
_SYNC_HEALTHY = (
    "SUCCESS",
    "ENABLED",
    "ENABLE",
    "UP TO DATE",
    "UPTODATE",
    "IN SYNC",
    "INSYNC",
    "COMPLETE",
    "COMPLETED",
    "DONE",
    "OK",
)

NOT_ASSESSED = (
    NotAssessed(
        subject="failovertest",
        reason=(
            "of een failover werkelijk slaagt is met een configuratielezing niet vast te"
            " stellen; daar is een failovertest voor nodig"
        ),
    ),
    NotAssessed(
        subject="configuratie van de partner",
        reason=(
            "deze export komt van een appliance; of de partner dezelfde configuratie"
            " draagt vraagt een tweede scan en een vergelijking"
        ),
    ),
)


@dataclass(frozen=True)
class HaDimension:
    """One of the four dimensions of design row A4, with its one state word.

    ONE shape for all four, deliberately: the certainty rule, the blocking
    rule and the rendering are identical for every dimension, and four copies
    of them would be four places for the vocabulary to drift.

    `state` is the whole certainty rule: `onbevestigd` is the only word of
    this vocabulary that is not established, so a dimension cannot carry that
    word and a `[vastgesteld]` marker at the same time - and it cannot carry
    it without a reason either (that is `Finding`'s rule, enforced here one
    layer earlier so the defect surfaces at the derivation, not at the render).
    """

    label: str
    state: str
    evidence: str
    reason: str = ""
    # The state at which this dimension does NOT hold up a change. `aan` for
    # the two dimensions that describe a working pair, `uit` for the two that
    # describe a problem (a forced node, a config difference).
    safe_state: str = ON
    # A dimension whose WORD stays what the ledger
    # deliberately settled on - never downgraded by this - but whose
    # verdict rests on a field this version could not observe on ANY row.
    # The ledger kept the WORD `aan` for "no sync result observed"
    # deliberately, citing NSHC; it did not settle the CERTAINTY, and the
    # Global Constraint ("niets [vastgesteld] zonder een geslaagde lezing")
    # still applies to that separately. Carrying the gap ON the dimension
    # (instead of a second return channel next to `HaDimension`) means
    # `to_finding()` and `ha_state()` read it as ONE source: the certainty
    # marker on the finding line, and the answer's own `read_gaps` listing -
    # one field, two consumers, like the rest of this module.
    read_gap: ReadGap | None = None

    def __post_init__(self) -> None:
        if self.label not in LABELS:
            raise ValueError(f"onbekend dimensielabel: {self.label!r}")
        if self.state not in OUTCOME_WORDS:
            raise ValueError(f"woord buiten het vocabulaire van deze tool: {self.state!r}")
        if self.state == NOT_APPLICABLE and self.read_gap is not None:
            # NSHC keeps the two apart at the source (naReason 'scope'
            # against 'readgap') and so does this: a control that does not
            # apply is not a source that could not be read.
            raise ValueError("niet van toepassing is geen leesgat")
        if self.safe_state not in (ON, OFF):
            raise ValueError(f"een veilige stand is aan of uit, niet {self.safe_state!r}")
        if not self.evidence.strip():
            raise ValueError("een dimensie zonder bewijs mag niet bestaan")
        if self.state == UNCONFIRMED and not self.reason.strip():
            raise ValueError("onbevestigd zonder reden is een stille aanname")

    @property
    def established(self) -> bool:
        if self.read_gap is not None:
            return False
        return self.state != UNCONFIRMED

    @property
    def blocking(self) -> bool:
        """Does this dimension hold up a change on the primary?

        `onbevestigd` blocks by construction: it is never the safe state, so
        an unread field can never pass for a healthy one.

        `niet van toepassing` is the one word that does NOT block, and it is
        the only exception for the same reason NSHC gives a scope-excluded
        control `Severity='None'`: a control that does not apply carries no
        risk weight. Claiming that a role distribution which does not exist
        holds up a change would be a risk this read never found - the
        mirror image of the silent green this tool exists to prevent, and
        just as untrue. A standalone appliance still blocks on whatever the
        two dimensions that DO apply say (measured on the real export with
        one configuration line added: config-drift `aan` blocks).
        """
        if self.state == NOT_APPLICABLE:
            return False
        return self.state != self.safe_state

    def to_finding(self) -> Finding:
        # THE ANSWER TO THE QUESTION, ON EVERY LINE. The tool asks "mag ik hier
        # op de primary wijzigen", and the four words alone do not answer it:
        # this answer reads `uit / uit / uit / aan`, in which two `uit` lines
        # hold up the change, one does not, and the `aan` line does. That
        # polarity used to live only in this module's docstring, and
        # `HaResult.blockers` - the summary `preflight.py` reads - reached the
        # machine consumer and not the human reading the same tool.
        #
        # Deliberately NOT a fifth finding and NOT a fifth word: `veilig` /
        # `nog niet veilig` would overlap `preflight.py`'s own 2.1.1
        # vocabulary (design 2.1 forbids that), and this module has
        # four labels, not five. This is a clause on the evidence the
        # dimension already carries, derived from `blocking` in ONE place, so
        # a blocking dimension cannot be rendered as a free one.
        held = "houdt de wijziging tegen" if self.blocking else "houdt de wijziging niet tegen"
        return Finding(
            subject=self.label,
            outcome=self.state,
            certainty=Certainty.ESTABLISHED if self.established else Certainty.NOT_ESTABLISHED,
            evidence=f"{self.evidence}; {held}",
            # A dimension made NOT_ESTABLISHED by `read_gap` (state
            # otherwise ESTABLISHED, so `self.reason` is empty - the
            # UNCONFIRMED branch above already fills `reason` for every
            # other not-established case) falls back to the gap's own
            # reason - `Finding` itself requires one for a non-established
            # certainty, and the gap's reason is exactly why this one is not.
            reason=self.reason or (self.read_gap.reason if self.read_gap is not None else ""),
            # The four labels are THIS PRODUCT's own words, not appliance
            # object names. The disclosure seam collects every finding subject
            # as a name to mask unless its author says otherwise, and a masked
            # "config-drift" says nothing at all - the lesson of
            # `overzicht._label_finding`, applied here from the start.
            subject_is_name=False,
        )


@dataclass(frozen=True)
class HaResult:
    """The four dimensions plus what was counted to reach them.

    `node_count` is only meaningful together with `node_count_established`:
    zero nodes out of an unreadable source and zero nodes out of a source that
    was read and was empty are two different statements, and a consumer that
    reads only the number would equate them.
    """

    roles: HaDimension
    sync: HaDimension
    forced: HaDimension
    drift: HaDimension
    pair: bool
    node_count: int
    node_count_established: bool

    @property
    def dimensions(self) -> tuple[HaDimension, ...]:
        return (self.roles, self.sync, self.forced, self.drift)

    @property
    def blockers(self) -> tuple[str, ...]:
        """The labels of every dimension that holds up a change, in reporting
        order. `preflight.py` (checks 3 and 4) reads this."""
        return tuple(d.label for d in self.dimensions if d.blocking)


def _objects_text(count: int) -> str:
    """Customer copy, so no broken plural - the rule of `answer._days_old`."""
    return "1 object" if count == 1 else f"{count} objecten"


def _text(row: dict, field: str) -> str:
    """The stripped text of a field, or "" for anything that is not text.

    Deliberately not `str(...)`: a number, a list or a JSON null is NOT a
    state, and turning one into text would make it look like one.
    """
    raw = row.get(field, _MISSING)
    return raw.strip() if isinstance(raw, str) else ""


def _shape(row: dict, field: str) -> str:
    """Names what sits at `field`: absent, or the SHAPE of what is there.

    Never the value. Delegates to `export.shape_or_missing_at` - the
    shared consolidation of what used to be this module's own copy of the
    idiom, and the container FORM of it, not a hand-built
    reconstruction of the same lookup.
    """
    return shape_or_missing_at(row, field)


def _unreadable_field(row: dict, field: str, vocabulary_name: str, **switches) -> str:
    """The reason for a field that was read but that this version cannot use.

    THE shape gate of this module. Every one of these fields comes out of an
    object file's CONTENT, which is SUPPLIED input (the export is handed to
    this product), and the disclosure seam masks only NAMES - so text out of
    such a field reaches the model UNMASKED unless something stops it. This
    is that something: `answer.repeatable_token`, the one shape gate of this
    product, with the switches that fit the vocabulary of the field in
    question. A value that passes may be REPEATED (it is a short, upper-case
    NITRO token, and repeating it is what lets an operator diagnose the
    appliance); a value that does not is named by its SHAPE and never
    reproduced.

    The claim the text makes is true at EVERY ground on which it can be
    printed: the caller has already established that the value is not one this
    version knows.
    """
    raw = row.get(field, _MISSING)
    token = repeatable_token(raw, **switches)
    if token is not None:
        return f"{field} draagt {token}, geen waarde die deze versie als {vocabulary_name} kent"
    if not isinstance(raw, str) or not raw.strip():
        return f"{field} draagt {_shape(row, field)} in plaats van {vocabulary_name}"
    return f"{field} draagt een waarde zonder de vorm van {vocabulary_name}"


# The switches per vocabulary - written out per field rather than left to the
# defaults, so the gate at each call site is as tight as the vocabulary it
# guards and a reader can see WHY.
#
# A `hastatus` and a `hasynchronizationstatus` are upper-case and may carry a
# SPACE ("UP TO DATE", "IN PROGRESS", "PARTIAL FAIL"); `haprop` and `hasync`
# are ONE word (ENABLED/DISABLED); a role is at most two words ("Claiming
# primary") and carries neither separator.
#
# CORRECTED: this comment used to cite "PARTIAL FAIL" as the
# HYPHEN-carrying example, and that value carries a SPACE. Measured over every
# HA status value NSHC names - the healthy/fail/progress sets at
# `NshcHaDriftTruth.ps1:52-54`, the hastatus whitelist at
# `Invoke-NshcSecurityScorecard.ps1:737` and the not-up examples at :735
# ("UNKNOWN", "DOWN", "UNKNOWN/DOWN") - NOT ONE carries a hyphen, so the
# switch is now as tight as the vocabulary really is. That makes this gate
# tighter than `overzicht._repeatable` on the same `hastatus` field, and
# deliberately so: tighter costs at most an echo (the value is then named by
# its shape, which is the safe side), looser costs a leak.
_STATUS_SWITCHES = {"max_words": 4, "allow_underscore": False, "allow_hyphen": False}
_FLAG_SWITCHES = {"max_words": 1, "allow_underscore": False, "allow_hyphen": False}
# The role gate is nearly a dead echo path by construction, and deliberately
# so: `repeatable_token` demands a leading capital followed by UPPER CASE, and
# every known role is mixed case ("Primary"), so no role this version knows can
# ever be repeated - only an all-upper-case value it does NOT know can, which
# is exactly the value an operator needs to see to diagnose the appliance.
_ROLE_SWITCHES = {"max_words": 2, "allow_underscore": False, "allow_hyphen": False}


def _role_field(row: dict) -> str:
    """WHICH field carries the role of this node: `state`, with
    `hacurmasterstate` as the fallback NSHC uses
    (Invoke-NshcSecurityScorecard.ps1:671-675). Always names one of the two,
    so a refusal text can say which field it is talking about."""
    return "state" if _text(row, "state") else "hacurmasterstate"


def _role_of(row: dict) -> str | None:
    """The role of one node as a word of `HA_STATES`, or None.

    None covers BOTH kinds of ignorance the caller must not conflate with a
    secondary: a field that is not readable text at all, and a field that IS
    readable but carries a word this version does not know. MEASURED while
    writing the tests for this module: without the vocabulary check, a second
    node carrying an unrecognizable role left the count at "one Primary" and
    the answer said `rolverdeling: aan` - a healthy pair claimed on a node
    whose role was never understood. NSHC has the same hole (its
    `haveAllRoles` only asks whether the field is non-empty,
    Invoke-NshcSecurityScorecard.ps1:677); this product does not, because a
    value only means something if this version knows it.

    Returns the word of the VOCABULARY, not the casing this export happened to
    use - one spelling per role in the text, the rule of `overzicht._known`.
    """
    raw = _text(row, "state") or _text(row, "hacurmasterstate")
    if not raw:
        return None
    folded = raw.casefold()
    for known in HA_STATES:
        if known.casefold() == folded:
            return known
    return None


def _roles_dimension(nodes: list[dict], base: str, pair: bool) -> HaDimension:
    """GJK-L1-HA-001: is there a healthy 1-Primary role distribution?

    Healthy is what NSHC's all-clear branch spells out (NshcHaTruth.ps1:198,
    "exactly 1 Primary, others Secondary") - not merely "exactly one node
    says Primary", which would let any other value pass for a secondary.

    Deliberately does NOT read `hastatus`: NSHC's HA-001 does not either - the
    health of that field is HA-003's question, and this module keeps the four
    controls on their own four dimensions so a reader can tell WHICH one is
    wrong.
    """
    if not pair:
        # The applicability word, not a state - see `_STANDALONE`.
        return HaDimension(label=ROLES_LABEL, state=NOT_APPLICABLE, evidence=base)
    roles: list[str] = []
    for position, node in enumerate(nodes, start=1):
        role = _role_of(node)
        if role is None:
            # NshcHaTruth.ps1:125-136 (role-incomplete -> UNKNOWN): without a
            # role on every node there is no role distribution at all. A
            # POSITION, never a node name or a node id - both come out of the
            # export.
            field = _role_field(node)
            return HaDimension(
                label=ROLES_LABEL,
                state=UNCONFIRMED,
                evidence=base,
                reason=f"rij {position}: " + _unreadable_field(node, field, "een HA-rol", **_ROLE_SWITCHES),
            )
        roles.append(role)
    primaries = sum(1 for role in roles if role == PRIMARY)
    secondaries = sum(1 for role in roles if role == SECONDARY)
    counted = f"{base}; {primaries} {PRIMARY} en {secondaries} {SECONDARY} van {len(nodes)} nodes"
    healthy = primaries == 1 and secondaries == len(nodes) - 1
    return HaDimension(label=ROLES_LABEL, state=ON if healthy else OFF, evidence=counted)


def _rows_text(positions: list[int]) -> str:
    """ "rij 2" or "rij 1 en rij 2" - customer copy, so no bare list."""
    rows = [f"rij {position}" for position in positions]
    return rows[0] if len(rows) == 1 else ", ".join(rows[:-1]) + f" en {rows[-1]}"


def _flag_reading(nodes: list[dict]) -> str:
    """What `haprop` and `hasync` LITERALLY say on the nodes that were read.

    The MEASURED fact next to the reasoning. On a standalone this dimension
    says `uit` because there is no partner to propagate to - while the export
    may well carry `haprop=ENABLED`; an operator holding the answer next to
    the appliance then sees a contradiction the answer cannot resolve unless
    it names what it read. NSHC prints the same pair the same way
    (`Invoke-NshcSecurityScorecard.ps1:714, :721`).

    Echoes only THIS module's own constants, after an exact match against
    them - never the spelling the export happened to use, so no shape gate is
    needed or wanted here.
    """
    if not nodes:
        return "haprop en hasync zijn op geen node gelezen"
    return " en ".join(f"{field}={_flag_phrase(nodes, field)}" for field in ("haprop", "hasync"))


def _flag_phrase(nodes: list[dict], field: str) -> str:
    values = [_text(node, field).upper() for node in nodes]
    if all(value == ENABLED for value in values):
        return ENABLED
    if any(DISABLED in value for value in values):
        return DISABLED
    return f"geen uitdrukkelijke {ENABLED}"


def _sync_dimension(nodes: list[dict], base: str, pair: bool) -> HaDimension:
    """GJK-L1-HA-002: are propagation and sync in effect?

    The order is NSHC's (Invoke-NshcSecurityScorecard.ps1:706-720): DISABLED
    first (a deliberate misconfiguration, an established `uit`), then the
    demand that BOTH fields are explicitly ENABLED on EVERY node (anything
    else is no proof of healthy propagation, never a false green), and only
    then the sync RESULT - which is read against the CLOSED vocabulary of
    `_SYNC_HEALTHY` / `_SYNC_FAILED` / `_SYNC_RUNNING`, per node.
    """
    if not pair:
        # A single node propagates to nobody. The evidence says so rather
        # than leaving the reader to infer it from the word alone - and it
        # names the two flags it read, so the measured fact and the
        # reasoning stand side by side. The applicability word, not a
        # state - see `_STANDALONE`.
        return HaDimension(
            label=SYNC_LABEL,
            state=NOT_APPLICABLE,
            evidence=(f"{base}; {_flag_reading(nodes)}; geen partner om configuratie naartoe te propageren"),
        )
    # Node-outer, field-inner, exactly like the ENABLED loop below it: the two
    # loops walk the same nodes and the same fields, and one of them walking
    # them the other way round would be a difference a reader has to explain.
    for position, node in enumerate(nodes, start=1):
        for field in ("haprop", "hasync"):
            if DISABLED in _text(node, field).upper():
                # `rij N`, like every other statement of this module about one
                # node - never a node name or a node id, both of which come
                # out of the export.
                return HaDimension(
                    label=SYNC_LABEL,
                    state=OFF,
                    evidence=f"{base}; rij {position}: {field} is {DISABLED}",
                )
    for position, node in enumerate(nodes, start=1):
        for field in ("haprop", "hasync"):
            if _text(node, field).upper() != ENABLED:
                return HaDimension(
                    label=SYNC_LABEL,
                    state=UNCONFIRMED,
                    evidence=base,
                    reason=(
                        f"rij {position}: {_unreadable_field(node, field, 'een propagatievlag', **_FLAG_SWITCHES)};"
                        f" zonder een uitdrukkelijke {ENABLED} op elke node is er geen bewijs"
                        " van gezonde propagatie"
                    ),
                )
    enabled = f"{base}; haprop en hasync zijn {ENABLED} op elke node"
    statuses = [_text(node, "hasynchronizationstatus").upper() for node in nodes]
    if any(marker in status for status in statuses for marker in _SYNC_FAILED):
        return HaDimension(
            label=SYNC_LABEL,
            state=OFF,
            evidence=f"{enabled}; hasynchronizationstatus meldt een mislukte sync",
        )
    if any(marker in status for status in statuses for marker in _SYNC_RUNNING):
        # NSHC lumps IN PROGRESS with FAILED (both PARTIAL). Both block here
        # too, so the severity is the same - but a sync that is still RUNNING
        # is not a sync that FAILED, and this product owns a word for exactly
        # that difference.
        return HaDimension(
            label=SYNC_LABEL,
            state=UNCONFIRMED,
            evidence=enabled,
            reason=("hasynchronizationstatus meldt een lopende sync; een sync die nog loopt is geen bevestigde sync"),
        )
    # PER NODE from here, never `any()` across all of them: a node whose sync
    # result was never read must not be covered by its partner's.
    unobserved: list[int] = []
    for position, node in enumerate(nodes, start=1):
        raw = node.get("hasynchronizationstatus", _MISSING)
        if raw is _MISSING or (isinstance(raw, str) and not raw.strip()):
            # Absent or blank, treated identically here (both land in
            # `unobserved`, both keep the word `aan` - now with a ReadGap
            # when EVERY row is like this, see below). NSHC reads both
            # through one default (`Get-PropSafe ... ''`, :680) and groups
            # ALL THREE forms of "no sync result" the same way - but this
            # branch does NOT: a JSON `null` is neither `_MISSING` nor a
            # `str`, so it never reaches here at all. It falls through to
            # the `_SYNC_HEALTHY` check below with `_text()`'s empty
            # string, which is unknown to that closed vocabulary, and
            # returns UNCONFIRMED (`onbevestigd`) instead - a THIRD form
            # producing a SECOND word (absent -> `aan`, `""` ->
            # `aan`, JSON `null` -> `onbevestigd`). The deviation from NSHC
            # is on the SAFE side (null blocks rather than passing), so it
            # is left as is - but "treats them identically" was too strong
            # a claim before this correction, and it is load-bearing now
            # that `unobserved` decides whether the ReadGap above applies.
            unobserved.append(position)
            continue
        if statuses[position - 1] not in _SYNC_HEALTHY:
            # READ, and not a value this version knows. Never the bare `aan`
            # this branch used to fall through to: that is a green word on a
            # value nobody understood (hardening rule 6), and NSHC's own deep
            # sync truth refuses it too (NshcHaDriftTruth.ps1:80).
            return HaDimension(
                label=SYNC_LABEL,
                state=UNCONFIRMED,
                evidence=enabled,
                reason=(
                    f"rij {position}: "
                    + _unreadable_field(node, "hasynchronizationstatus", "een sync-status", **_STATUS_SWITCHES)
                ),
            )
    if unobserved:
        # NSHC keeps a PASS possible here and only lowers the confidence
        # ("geen sync-fout zien is geen sync-bewijs", :684-688): HA-002 is the
        # question whether propagation is ENABLED, and that IS established -
        # the sync RESULT is complementary evidence (:2622). This product has
        # no confidence axis, so it says the same thing in the evidence, and
        # it says WHICH rows it could not observe.
        gap = None
        if len(unobserved) == len(nodes):
            # The verdict-driving field
            # (hasynchronizationstatus) was observed on NO row at all - the
            # Global Constraint ("niets [vastgesteld] zonder een geslaagde
            # lezing") applies regardless of which WORD the ledger
            # deliberately settled on for this case. This ReadGap does not
            # change the word `aan` - it changes the CERTAINTY: the finding
            # renders `[niet vastgesteld]` and the gap itself appears under
            # "NIET VASTGESTELD", instead of a field nobody read standing as
            # `[vastgesteld]` on the tool that gates a write on the primary.
            # A PARTIALLY unobserved node (some rows read, some not) keeps
            # no gap here: at least one row's sync result really was read.
            gap = ReadGap(
                source=f"{RESOURCE}.hasynchronizationstatus",
                reason=f"hasynchronizationstatus niet waargenomen op {_rows_text(unobserved)}",
            )
        return HaDimension(
            label=SYNC_LABEL,
            state=ON,
            evidence=(f"{enabled}; hasynchronizationstatus niet waargenomen op {_rows_text(unobserved)}"),
            read_gap=gap,
        )
    return HaDimension(
        label=SYNC_LABEL,
        state=ON,
        evidence=f"{enabled}; hasynchronizationstatus meldt een geslaagde sync op elke node",
    )


def _forced_dimension(nodes: list[dict], base: str) -> HaDimension:
    """GJK-L1-HA-003: is a node forced into a state it will not leave?

    Asked of every node that was read, pair or not: a forced `hastatus` on a
    single node is a real reading of a real field, and NSHC only skips the
    question there because its whole HA control family is out of scope on a
    standalone (naReason='scope'), not because the field says nothing.
    """
    if not nodes:
        # Zero nodes, out of a source that WAS read usably (status EMPTY, so
        # no read gap). "Geen node draagt een geforceerde stand" is vacuously
        # true over an empty set and used to be reported as an established,
        # non-blocking `uit` - a green word on nothing at all. There is no
        # reading here, so there is no established word either.
        return HaDimension(
            label=FORCED_LABEL,
            state=UNCONFIRMED,
            evidence=base,
            reason=("geen node gelezen, dus er is geen hastatus waaruit een geforceerde stand blijkt of niet blijkt"),
            safe_state=OFF,
        )
    # DISTINCT POSITIONS, and EVERY word matched. Both used to be wrong in the
    # same expression: this was a list over the CROSS PRODUCT of nodes and
    # words, and the evidence took the first word of it with the length of the
    # whole list as the node count. A pair of one STAYPRIMARY and one
    # STAYSECONDARY then read "STAYPRIMARY op 2 nodes" - false for the second
    # node - and one node carrying both words read "op 2 nodes" for one node.
    # The state word was right either way, but a `[vastgesteld]` line that
    # states a wrong count is not something this product may print.
    positions: list[int] = []
    matched: set[str] = set()
    for position, node in enumerate(nodes, start=1):
        status = _text(node, "hastatus").upper()
        hits = [word for word in FORCED_HASTATUS if word in status]
        if hits:
            positions.append(position)
            matched.update(hits)
    if positions:
        count = len(positions)
        # The words echoed are THIS module's own constants, matched
        # case-insensitively and printed in the module's own order - never the
        # spelling or the order the export happened to use.
        words = " en ".join(word for word in FORCED_HASTATUS if word in matched)
        return HaDimension(
            label=FORCED_LABEL,
            state=ON,
            evidence=f"{base}; hastatus draagt {words} op {count} node" + ("s" if count != 1 else ""),
            safe_state=OFF,
        )
    for position, node in enumerate(nodes, start=1):
        if _text(node, "hastatus").upper() not in HEALTHY_HASTATUS:
            # UNKNOWN, DOWN, empty: not-up. NOT a `uit` - "no forced state
            # seen" is not "no forced state" when the field itself is not one
            # this version can read.
            return HaDimension(
                label=FORCED_LABEL,
                state=UNCONFIRMED,
                evidence=base,
                reason=(f"rij {position}: " + _unreadable_field(node, "hastatus", "een HA-status", **_STATUS_SWITCHES)),
                safe_state=OFF,
            )
    return HaDimension(
        label=FORCED_LABEL,
        state=OFF,
        evidence=f"{base}; hastatus is gezond op elke gelezen node",
        safe_state=OFF,
    )


def _drift_dimension(export) -> tuple[HaDimension, tuple[ReadGap, ...]]:
    """GJK-L1-HA-004: does the running config differ from the saved config?

    Both files are hash-verified by export.py, so a difference is a difference
    between two files this product trusts - not between a file and a memory of
    one. What comes out is COUNTS: how many lines each side compared, and how
    many lines sit in one and not in the other - including a line that differs
    only in the part the credential filter withholds (a password changed and
    not saved), which is drift like any other. Where the collector had already
    withheld such a value on both sides and the headers say the configuration
    changed after the last save, the dimension is `onbevestigd`: no count can
    see that change. Never a line. A running-config line can carry a
    credential (design 3.6, unit 8).

    The comparison itself is `config_drift.read_comparison`, the ONE
    comparison this product makes between the two files (the header lines and
    the closing `Done` are not configuration and do not count; see that
    module). The evidence is that module's sentence too, so `ha_stand`,
    `config_drift` and pre-flight check 4 print the same numbers for the same
    export.
    """
    comparison, gaps = read_comparison(export)
    if comparison is None:
        return (
            HaDimension(
                label=DRIFT_LABEL,
                state=UNCONFIRMED,
                evidence=f"{RUNNING_CONFIG_FILE} en {SAVED_CONFIG_FILE}",
                reason="; ".join(gap.reason for gap in gaps),
                safe_state=OFF,
            ),
            gaps,
        )
    if comparison.undecided:
        # Both files were read; lines whose value the collector withheld
        # could carry the change the headers report. Not established, and
        # no read gap either - `config_drift.undecided_reason` says why.
        return (
            HaDimension(
                label=DRIFT_LABEL,
                state=UNCONFIRMED,
                evidence=comparison_evidence(comparison),
                reason=undecided_reason(comparison),
                safe_state=OFF,
            ),
            (),
        )
    return (
        HaDimension(
            label=DRIFT_LABEL,
            state=ON if comparison.drift else OFF,
            evidence=comparison_evidence(comparison),
            safe_state=OFF,
        ),
        (),
    )


def ha_result(export) -> tuple[HaResult, tuple[ReadGap, ...]]:
    """The four dimensions of design row A4, plus every read gap they cost.

    The read gaps are returned separately rather than folded into the
    dimensions: a dimension says WHAT this version could establish, a read gap
    says WHICH SOURCE it could not get usable, and this product keeps those
    two apart everywhere (see the module docstring of answer.py).
    """
    drift, gaps = _drift_dimension(export)
    nodes, node_gap = export.objects(RESOURCE)
    if node_gap is not None:
        # Not a single statement about a pair out of a source that was not
        # read. All three hanode dimensions become `onbevestigd`, each with
        # the gap's own reason, and the gap itself travels on so the answer
        # can never call itself complete.
        gaps = (node_gap,) + gaps
        return (
            HaResult(
                roles=HaDimension(label=ROLES_LABEL, state=UNCONFIRMED, evidence=RESOURCE, reason=node_gap.reason),
                sync=HaDimension(label=SYNC_LABEL, state=UNCONFIRMED, evidence=RESOURCE, reason=node_gap.reason),
                forced=HaDimension(
                    label=FORCED_LABEL,
                    state=UNCONFIRMED,
                    evidence=RESOURCE,
                    reason=node_gap.reason,
                    safe_state=OFF,
                ),
                drift=drift,
                pair=False,
                node_count=0,
                node_count_established=False,
            ),
            gaps,
        )
    pair = len(nodes) >= 2
    base = f"{RESOURCE}: {_objects_text(len(nodes))}"
    if not pair:
        base = f"{base}; {_STANDALONE}"
    return (
        HaResult(
            roles=_roles_dimension(nodes, base, pair),
            sync=_sync_dimension(nodes, base, pair),
            forced=_forced_dimension(nodes, base),
            drift=drift,
            pair=pair,
            node_count=len(nodes),
            node_count_established=True,
        ),
        gaps,
    )


def ha_state(export, knowledge: Knowledge) -> Answer:
    result, gaps = ha_result(export)
    # A dimension can carry its OWN read gap now
    # (`HaDimension.read_gap`, see `_sync_dimension`) - separate from the
    # coarse, whole-source gaps `ha_result()` already returns (a missing
    # config/hanode, an unreadable running/saved config). Folding both into
    # ONE list here, generically over every dimension, means a later
    # dimension gaining its own gap needs no second wiring point.
    dimension_gaps = tuple(dimension.read_gap for dimension in result.dimensions if dimension.read_gap is not None)
    return Answer(
        question=QUESTION,
        findings=[dimension.to_finding() for dimension in result.dimensions],
        read_gaps=list(gaps) + list(dimension_gaps),
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_ha_sources(export) -> tuple[str, ...]:
    """Every appliance object name `ha_state()` can print - the NINTH family of
    `disclosure.names_from_export()`.

    Today this answer prints COUNTS and words, never a node name - the four
    dimensions are deliberately node-free, and a test pins that. This family
    exists anyway, and it is not decoration:
    `overzicht.names_in_overview_sources()` already harvests the same
    `config/hanode` names for exactly the same reason, and a later version of
    THIS module that names a node ("rij 1 staat op STAYSECONDARY" is one
    small step from "NODE-B staat op STAYSECONDARY") must not be able to leak
    one because nobody remembered to add the family. Over-collecting is
    harmless; a name too few is a leak.

    Fail-closed by construction, like every other family: a source that cannot
    be read yields no names, and a name this export never read can never reach
    a text either.
    """
    names: set[str] = set()
    rows, _gap = export.objects(RESOURCE)
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())
    return tuple(sorted(names))
