"""The confirmation code between a proposal and an action.

Why this exists: a language model in the loop can call any tool it sees.
The seven writing tools therefore never act on a first call - they return a
proposal and a code, and only a second call carrying that code acts. The
code cannot be derived by the model: it is random, it exists only in the
memory of this server process, it lives ten minutes, it is single-use, and
it is bound to exactly one tool with exactly these arguments on exactly this
target - the label the write script reports AND the allowlist section the
call named. A code presented with a different action is burnt on the spot
(fail-closed): a code that was seen next to the wrong action is not to be
trusted for the right one either.

The alphabet leaves out 0/O and 1/I: the code is read aloud and typed by a
human, and those pairs are the classic misreads.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 6
TTL_S = 600

# The alphabet of the per-proposal marker: the FULL A-Z, unlike the code
# alphabet above. That one leaves out 0/O and 1/I because a code is read aloud
# and typed by a human and those pairs are the classic misreads; a marker is
# never typed, so nothing has to go. Twenty-six is at the same time the hard
# ceiling design 3.7 puts on simultaneous proposals.
MARKER_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# THE one rendering of a marker. Design 3.7 wants it identical across the
# proposal text, all three code channels and the action log. `marker_line()`
# has three callers who all take that literally instead of writing
# "voorstel" again: `code_channel._message()` (for the `venster` and
# `bestand` channels), `code_channel.SsoCodeChannel.__call__` (for the
# `sso` channel's `aanduiding` field) and `mcp_server._with_marker()` (for
# the proposal text the model reads). "Identical in venster, bestand, sso
# and the proposal" is therefore a structural property today, not a plan;
# the action log's own `voorstel` field stores the raw marker letter as a
# JSON value, never rendered prose, so it has no rendering to share here.
# A new channel kind should still inherit the rendering by
# calling this function rather than writing "voorstel" again.
MARKER_PREFIX = "voorstel"


def marker_line(marker: str) -> str:
    """THE one rendering of a marker - and, therefore, the ONE place that
    validates it (ONE RULE, ONE OWNER means the
    guard belongs here, not in every caller). `marker` must be exactly one
    letter from `MARKER_LETTERS`; anything else fails closed. Two concrete
    risks this closes: a multi-line marker could forge a second
    `bevestigingscode:` line inside the operator's own text - the single
    trust anchor of the whole write path - and the confirmation CODE itself
    (six characters, a different alphabet) must never be able to reach this
    line either. Both callers today (`code_channel._message()`, passing the
    presenter's sixth parameter, and `mcp_server._with_marker()`, passing
    that same value to the proposal text) only ever pass what
    `ConfirmationStore.marker(code)` returns, which is always one letter -
    so neither risk is reachable through them. The guard still lives here
    and not on their discipline, because the next caller (a new channel
    kind) is not hypothetical.

    `isinstance` runs BEFORE `len()`,
    not after. Before this, `length = len(marker)` ran first and a marker
    without `__len__` (an int, `None`, ...) raised a bare `TypeError` there,
    never reaching the `ValueError` below - so "anything else fails closed"
    was only true of str-like values, not of "anything". Checking the type
    first makes the docstring's claim literally true: every non-letter
    input, sized or not, now fails the same closed way.
    """
    if not isinstance(marker, str):
        raise ValueError(
            f"marker moet exact een letter uit MARKER_LETTERS zijn (kreeg geen str maar type {type(marker).__name__})"
        )
    length = len(marker)
    if length != 1 or marker not in MARKER_LETTERS:
        raise ValueError(
            "marker moet exact een letter uit MARKER_LETTERS zijn "
            f"(kreeg lengte {length}, type {type(marker).__name__})"
        )
    return f"{MARKER_PREFIX} {marker}"


class ConfirmError(Exception):
    """The code does not authorize this action. Never silent."""


class TooManyProposals(ConfirmError):
    """Twenty-six proposals are already outstanding. Never silent.

    A ConfirmError, not a bare Exception: this store already has one
    refusal type that reaches the operator honestly (mcp_server.py catches
    `ConfirmError` at the call sites that can raise one and renders it
    through `_failure()`, which comes back out as a `ToolError` and so
    passes `mask_error()` unchanged). This refusal takes that SAME route -
    the module already had a way to be honest about a refusal, and this is
    another one, not a second mechanism.
    """


# The one text for "this code names nothing this store holds" - used by both
# `marker()` and `redeem()`'s first check. One constant so the two cannot
# drift apart on what is, word for word, the same sentence.
_CODE_ONBEKEND_OF_GEBRUIKT = "bevestigingscode onbekend of al gebruikt; vraag een nieuw voorstel aan"

# The one text for "this proposal's ten minutes are up" - used by both
# `marker()` and `redeem()`. One constant for the
# same reason as the one above: `marker()` used to purge the entry
# before looking it up, so a caller who read the letter first and redeemed
# second got `_CODE_ONBEKEND_OF_GEBRUIKT` for a proposal that had, in fact,
# simply expired - two call orders, two different sentences for the SAME
# situation. A shared constant is what keeps this fixed: neither method can
# drift onto its own wording for "verlopen" again.
_CODE_VERLOPEN = "bevestigingscode is verlopen (tien minuten); vraag een nieuw voorstel aan"


def _normalize_code(code: str) -> str:
    """The one place a presented code is folded to its canonical form:
    every whitespace character removed, case folded to upper. `marker()`
    and `redeem()` both look a code up by this form, so the two cannot
    drift apart on which entry a code names."""
    return "".join(str(code).split()).upper()


def _fingerprint(tool: str, arguments: dict, target: str, section: str = "") -> str:
    """`target` is the label the write script reports with [TARGET];
    `section` is the allowlist section the call named with `doel`. Both
    count: the script forms its label from its own facts, not from the
    section, so two sections that allow the same action see the SAME label -
    and a code proposed for one of them must not act under the other."""
    canonical = json.dumps(
        {"tool": tool, "arguments": arguments, "doel": target, "sectie": section},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


# After this many failed attempts an outstanding code is burned. Five, because
# it is far above what a human mistypes and far below anything a guesser can
# use: the key space is 32^6, so five guesses buy 4,7e-9 of it.
MAX_ATTEMPTS = 5


@dataclass
class _Pending:
    fingerprint: str
    expires_at: float
    marker: str
    failures: int = 0


class ConfirmationStore:
    def __init__(
        self,
        now=time.monotonic,
        ttl_s: int = TTL_S,
        *,
        max_attempts: int = MAX_ATTEMPTS,
        on_burn=None,
    ) -> None:
        self._now = now
        self._ttl = ttl_s
        self._max_attempts = max_attempts
        # Called with the NUMBER of codes this failure burned, never with a
        # code: the operator has to learn that his proposal is dead, and the
        # channel that carried the code is where he is looking.
        self._on_burn = on_burn
        self._pending: dict[str, _Pending] = {}
        # Where the next letter is looked for. A CURSOR and not "the lowest
        # free letter": design 3.7 says the series restarts at A only when NO
        # proposal is outstanding, and that is a different rule. An operator
        # whose `voorstel A` just disappeared must not get a fresh A next to
        # the `voorstel B` that is still on his screen.
        self._cursor = 0

    def _purge(self) -> None:
        """Drops every entry whose ten minutes are up.

        An expired code was already REFUSED - the
        clock check in `redeem()` below has always been there - but it only
        left the store if someone happened to present it. A proposal nobody
        ever confirms therefore stayed in memory for the life of the server
        process, and a caller controls how many of those there are simply by
        asking for proposals. Sweeping on both doors that touch the store
        keeps it bounded by what is actually LIVE.

        Never a security claim: an expired entry could not authorize anything
        before this, and cannot now. This is hygiene, and it is written down
        as hygiene.
        """
        now = self._now()
        for code in [c for c, pending in self._pending.items() if now > pending.expires_at]:
            del self._pending[code]

    def _allocate_marker(self) -> str:
        """The next free letter, in order of issue.

        Called AFTER `_purge()`, so an expired proposal has already released
        its letter: the letter lives on the entry and nowhere else, which is
        why there is no second piece of bookkeeping here that could drift out
        of step with the store itself.

        Documented boundary: the cursor remembers where the search should
        continue, not a history of every letter ever freed, so it can wrap
        all the way around the alphabet and land back on a letter that was
        freed early while later ones are still outstanding. With A through Z
        all issued and only A then redeemed, the next call hands back A
        while B through Z are still on the operator's screen - the one case
        where a freed letter is reused before EVERYTHING is gone, which is
        exactly what rule 3 otherwise prevents. It only happens at 25
        genuinely outstanding proposals (the alternative there is a spurious
        refusal with room still free), and no TWO open proposals ever share
        a letter either way - but it is a real edge of the stated rule, so
        it is written down here rather than left for someone to rediscover.
        """
        if not self._pending:
            self._cursor = 0
        in_use = {entry.marker for entry in self._pending.values()}
        for step in range(len(MARKER_LETTERS)):
            letter = MARKER_LETTERS[(self._cursor + step) % len(MARKER_LETTERS)]
            if letter not in in_use:
                self._cursor = (self._cursor + step + 1) % len(MARKER_LETTERS)
                return letter
        raise TooManyProposals(
            "er staan al 26 voorstellen open; bevestig of laat verlopen voordat u een nieuw voorstel aanvraagt"
        )

    def marker(self, code: str) -> str:
        """The letter of an OUTSTANDING proposal.

        Does NOT purge (this used to call
        `_purge()` first, exactly like `issue()`, and that was the bug).
        `_purge()` deletes an expired entry outright; if a caller then reads
        the letter here FIRST and `redeem()`s the SAME code SECOND,
        `redeem()`'s own pop finds nothing left and can never reach its own
        "verlopen" branch - the operator would get the generic "onbekend of
        al gebruikt" for a code that in fact simply expired, even though
        `redeem()` was deliberately written (pop-before-purge) to keep those
        two sentences apart.

        So this method now reads the entry AS IT STANDS and classifies it
        itself, instead of purging first and asking questions later: absent
        is `_CODE_ONBEKEND_OF_GEBRUIKT`, present but past its `expires_at` is
        `_CODE_VERLOPEN` - word for word the same sentence `redeem()` gives
        an expired code - and only a genuinely outstanding entry hands back
        its letter. The entry itself is left exactly where it was, for
        `redeem()` to pop and re-check next, exactly as it does when nobody
        called `marker()` first. Both call orders now end at the same,
        honest sentence.
        """
        entry = self._pending.get(_normalize_code(code))
        if entry is None:
            raise ConfirmError(_CODE_ONBEKEND_OF_GEBRUIKT)
        if self._now() > entry.expires_at:
            raise ConfirmError(_CODE_VERLOPEN)
        return entry.marker

    def issue(self, tool: str, arguments: dict, target: str, *, section: str) -> str:
        """`section` is the allowlist section the call named with `doel`. It
        is a REQUIRED keyword, on `redeem()` as well: a caller that forgets it
        fails loud instead of issuing a code that is bound to no section."""
        self._purge()
        # The letter FIRST, the code after it: a refused twenty-seventh
        # proposal must not leave a drawn code behind. Fail closed before
        # anything exists that could be redeemed.
        marker = self._allocate_marker()
        while True:
            code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
            if code not in self._pending:
                break
        self._pending[code] = _Pending(
            fingerprint=_fingerprint(tool, arguments, target, section),
            expires_at=self._now() + self._ttl,
            marker=marker,
        )
        return code

    def redeem(self, code: str, tool: str, arguments: dict, target: str, *, section: str) -> None:
        """Spends `code` only if it is live and bound to this exact tool,
        arguments, target and allowlist section. The failure counter below
        keys on the SAME fingerprint, section included. `section` is
        required here as on `issue()`, so no caller can leave it out on both
        sides and silently fall back to a code without that binding.

        The fingerprint-mismatch branch below is deliberately notice-free: a
        guess that carries the real code but the wrong fingerprint still pops
        and destroys the real entry before the mismatch is even checked, so
        neither `_count_failure` nor `on_burn` fires for it. The operator gets
        no signal, and his own later redeem of the real code reads "onbekend
        of al gebruikt" - the wrong sentence for what actually happened. Left
        as-is here: the probability is negligible and the pop-first ordering
        below is load-bearing. A later workstream's action log is where this
        branch should become visible to an operator.
        """
        normalized = _normalize_code(code)
        # pop FIRST: whatever happens below, this code is spent.
        pending = self._pending.pop(normalized, None)
        # Sweep AFTER the pop, never before it: a sweep that ran first would
        # remove the presented code itself when it is expired, and the caller
        # would read "onbekend of al gebruikt" for a code that is simply
        # verlopen. Two different situations, two different sentences - the
        # honest one is decided below, on `pending`.
        self._purge()
        if pending is None:
            # SECURITY 10: every unknown code counts against the
            # proposal it was guessed at; after MAX_ATTEMPTS the real code is
            # burned. Uses the fixed sentence integrated on 10-9-2026.
            self._count_failure(_fingerprint(tool, arguments, target, section))
            raise ConfirmError(_CODE_ONBEKEND_OF_GEBRUIKT)
        if self._now() > pending.expires_at:
            raise ConfirmError(_CODE_VERLOPEN)
        if pending.fingerprint != _fingerprint(tool, arguments, target, section):
            raise ConfirmError(
                "bevestigingscode hoort bij een andere handeling of een ander doel en is "
                "daarmee ongeldig geworden; vraag een nieuw voorstel aan"
            )

    def _count_failure(self, fingerprint: str) -> None:
        """Counts one wrong guess against every outstanding proposal WITH THIS
        FINGERPRINT, and burns the ones that reach the limit.

        Keyed on the fingerprint and deliberately not on the typed code: a
        guessed code belongs to no issued code, so a counter per code would
        only ever see expired codes and fingerprint mismatches - and would miss
        the brute force that was measured (1.020.434 redeem() calls per second,
        and after 2.040.869 failures the real code still worked). Whoever wants
        an action executed has to present the REAL fingerprint of that action,
        so his attempts land on the proposal he is attacking and nowhere else.
        That benchmark is an in-process number, not an attacker's rate: every
        redeem() reachable in production runs behind `validate()` and a
        PowerShell preview (dry) run of the write script in mcp_server.py,
        which precedes every reachable redeem attempt, so one guess costs one
        round-trip against the real appliance and the realistic hit
        probability over a code's whole lifetime stays around 1e-6 - move
        `redeem()` ahead of that preview, or add any cheaper refusal path, and
        it stops being true.

        Not on every outstanding proposal, and that is the point of the key: a
        guesser cannot burn a proposal he is not attacking. He CAN still burn
        the one he IS attacking, after five guesses, once he has its
        fingerprint - and in this file's threat model (see the module
        docstring) the caller who places the tool call always has it, since
        he authored the arguments and the target himself. A per-proposal
        guess cap and immunity to a fingerprint-aware attacker cannot both
        hold; this trade is deliberate.

        A MISMATCHED code is never counted here: its entry has already been
        popped by `redeem()` before this runs, so there is nothing left to
        protect. An EXPIRED code is only left uncounted while its entry
        SURVIVES to be popped by the same `redeem()` call that notices the
        expiry - once any `issue()` or
        `redeem()` has already swept it (`_purge()`), re-presenting that same
        code no longer finds an entry to pop, lands in the branch below
        instead, and IS counted. Reachable: a proposal expires, the operator
        asks for a new one with identical arguments (a fresh `issue()` purges
        the old entry), then pastes the old, now-purged code.
        """
        burned = 0
        for code in list(self._pending):
            entry = self._pending[code]
            if entry.fingerprint != fingerprint:
                continue
            entry.failures += 1
            if entry.failures >= self._max_attempts:
                del self._pending[code]
                burned += 1
        if burned and self._on_burn is not None:
            try:
                self._on_burn(burned)
            except Exception:  # noqa: BLE001 - a notice must never break a refusal
                pass
