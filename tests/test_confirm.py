"""The confirmation code is the one thing a language model cannot produce
by itself: it only exists after a proposal, it lives ten minutes, it is
single-use and it is bound to exactly one action on one target."""

from __future__ import annotations

import re
import threading

import pytest

from nsmcp.confirm import (
    TTL_S,
    ConfirmationStore,
    ConfirmError,
    TooManyProposals,
    marker_line,
)

# The allowlist section every code in this file is issued and redeemed for.
# `section` is a required keyword of `issue()` and `redeem()`; a test that is
# about the section itself names its own.
SECTION = "lab"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _store():
    clock = Clock()
    return ConfirmationStore(now=clock), clock


def test_code_has_six_characters_from_the_unambiguous_alphabet():
    store, _ = _store()
    code = store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    assert re.fullmatch(r"[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}", code)


def test_matching_redeem_succeeds_once():
    store, _ = _store()
    args = {"dienst": "sg", "lid": "web01"}
    code = store.issue("dienst_lid_uitschakelen", args, "lab", section=SECTION)
    store.redeem(code, "dienst_lid_uitschakelen", args, "lab", section=SECTION)
    with pytest.raises(ConfirmError, match="al gebruikt"):
        store.redeem(code, "dienst_lid_uitschakelen", args, "lab", section=SECTION)


def test_expired_code_is_refused():
    store, clock = _store()
    args = {"dienst": "sg", "lid": "web01"}
    code = store.issue("dienst_lid_uitschakelen", args, "lab", section=SECTION)
    clock.t += TTL_S + 1
    with pytest.raises(ConfirmError, match="verlopen"):
        store.redeem(code, "dienst_lid_uitschakelen", args, "lab", section=SECTION)


@pytest.mark.parametrize(
    "tool, args, target",
    [
        ("dienst_lid_inschakelen", {"dienst": "sg", "lid": "web01"}, "lab"),
        ("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web02"}, "lab"),
        ("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab2"),
    ],
)
def test_code_bound_to_another_action_is_refused_and_burnt(tool, args, target):
    store, _ = _store()
    original = {"dienst": "sg", "lid": "web01"}
    code = store.issue("dienst_lid_uitschakelen", original, "lab", section=SECTION)
    with pytest.raises(ConfirmError, match="andere handeling"):
        store.redeem(code, tool, args, target, section=SECTION)
    # A code seen with the wrong action is burnt: the original no longer works either.
    with pytest.raises(ConfirmError, match="al gebruikt"):
        store.redeem(code, "dienst_lid_uitschakelen", original, "lab", section=SECTION)


def test_unknown_code_is_refused():
    store, _ = _store()
    with pytest.raises(ConfirmError, match="onbekend"):
        store.redeem("ABCDEF", "dienst_lid_uitschakelen", {}, "lab", section=SECTION)


def test_redeem_is_case_and_whitespace_tolerant():
    store, _ = _store()
    args = {"dienst": "sg", "lid": "web01"}
    code = store.issue("dienst_lid_uitschakelen", args, "lab", section=SECTION)
    store.redeem(f"  {code.lower()} ", "dienst_lid_uitschakelen", args, "lab", section=SECTION)


def test_argument_order_does_not_matter_for_the_binding():
    store, _ = _store()
    code = store.issue("certificaat_vervangen", {"dienst": "d", "nieuwcert": "c"}, "lab", section=SECTION)
    store.redeem(code, "certificaat_vervangen", {"nieuwcert": "c", "dienst": "d"}, "lab", section=SECTION)


def test_the_section_is_a_required_keyword_of_issue_and_redeem():
    """A caller that leaves out the allowlist section fails loud. With an
    empty default, issuing AND redeeming without it still matched, so a
    caller that forgot it on both sides silently lost the binding to the
    section without any test turning red."""
    store, _ = _store()
    args = {"dienst": "sg", "lid": "web01"}
    with pytest.raises(TypeError):
        store.issue("dienst_lid_uitschakelen", args, "lab")
    code = store.issue("dienst_lid_uitschakelen", args, "lab", section="lab-a")
    with pytest.raises(TypeError):
        store.redeem(code, "dienst_lid_uitschakelen", args, "lab")
    store.redeem(code, "dienst_lid_uitschakelen", args, "lab", section="lab-a")


def test_a_code_issued_for_one_section_is_refused_and_burnt_under_another():
    """Same tool, same arguments, same label: only the section differs, and
    that is enough to refuse the code and spend it."""
    store, _ = _store()
    args = {"certnaam": "ster2027"}
    code = store.issue("certificaat_klaarzetten", args, "doel", section="lab-a")
    with pytest.raises(ConfirmError, match="andere handeling of een ander doel"):
        store.redeem(code, "certificaat_klaarzetten", args, "doel", section="lab-b")
    with pytest.raises(ConfirmError, match="al gebruikt"):
        store.redeem(code, "certificaat_klaarzetten", args, "doel", section="lab-a")


# ---------------------------------------------------------------------------
# C3 - the marker per proposal (design 3.7). A loose capital letter, handed out
# on issue and released the moment the proposal is confirmed, expired or burnt.
# It exists for one situation: two proposals open at once, two codes on the
# operator's screen, and no way to see which belongs to which. It carries
# nothing the proposal does not already imply - no object name, no target, no
# tool name, and no part of the code.
# ---------------------------------------------------------------------------


def test_two_simultaneous_proposals_get_different_letters():
    store, _ = _store()
    first = store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    second = store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    assert store.marker(first) == "A"
    assert store.marker(second) == "B"


def test_the_letter_carries_no_object_or_target_name():
    """Proven on the SHAPE plus the byte-for-byte line - deliberately NOT as
    `marker not in code`. Both draw from an uppercase alphabet, so a single
    letter lands inside a six-character code roughly one time in six by pure
    chance; a test that asserts otherwise is a coin flip dressed up as a
    guarantee. What IS provable, and what this test proves, is the full
    line: `regel == "voorstel A"` pins EVERY character of it, which already
    rules out any of the proposal's own values (tool, dienst, nieuwcert,
    doel, the code itself) appearing in it - a separate `waarde not in regel`
    loop after that exact-match assertion would be unable to fail for any
    input and was dropped for exactly that reason."""
    store, _ = _store()
    code = store.issue(
        "certificaat_vervangen", {"dienst": "gjkdemo_sg", "nieuwcert": "ster2027"}, "lab-01", section=SECTION
    )
    marker = store.marker(code)
    assert re.fullmatch(r"[A-Z]", marker)
    regel = marker_line(marker)
    assert regel == "voorstel A"


def test_marker_line_refuses_a_multi_line_marker():
    """`marker_line()`'s output is interpolated
    directly above `bevestigingscode:` in the operator's own channel text -
    the single trust anchor of the whole write path. A multi-line `marker`
    could forge a second `bevestigingscode:` line inside that text, so this
    must fail closed before rendering, not after."""
    with pytest.raises(ValueError):
        marker_line("A\nbevestigingscode: AB2345")


def test_marker_line_refuses_anything_that_is_not_one_letter():
    """`MARKER_LETTERS` already defines what a marker may be; a caller
    that passes something else - including, in a later step, the
    confirmation CODE itself - must be refused here, in the ONE owner, not
    trusted on the caller's discipline. `"AB2345"` is deliberately code-
    shaped (six characters, the code alphabet): the exact value this guard
    exists to refuse."""
    for niet_een_letter in ("", "AB", "2", "a", "AB2345"):
        with pytest.raises(ValueError):
            marker_line(niet_een_letter)


def test_marker_line_refuses_a_non_string_without_a_typeerror_first():
    """Before this fix, `length =
    len(marker)` ran BEFORE the type was ever checked, so a marker without
    `__len__` raised a bare `TypeError` there and never reached the
    `ValueError` below - the guard's own docstring says 'anything else
    fails closed', and a `TypeError` escaping past this function is not
    that. `None` and an `int` are two different reasons `len()` would have
    raised (no `__len__` at all, versus one that exists on a different
    type) - both must fail the SAME closed way, as `ValueError`."""
    for niet_een_string in (None, 5, ["A"], object()):
        with pytest.raises(ValueError):
            marker_line(niet_een_string)


def test_the_letter_follows_the_order_of_issue_and_not_the_drawn_code():
    """The other half of the same claim: the letter is decided by WHEN a
    proposal was issued, never by WHAT was drawn. Two stores that draw two
    different codes hand out the same first letter."""
    first_store, _ = _store()
    second_store, _ = _store()
    a = first_store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    b = second_store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    assert a != b, "twee stores trokken dezelfde code (kans 32^-6); draai opnieuw"
    assert first_store.marker(a) == "A"
    assert second_store.marker(b) == "A"


def test_a_released_letter_is_reused_only_after_the_proposal_is_gone():
    store, _ = _store()
    first = store.issue("dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    second = store.issue("dienst_lid_inschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    assert (store.marker(first), store.marker(second)) == ("A", "B")
    # A is confirmed and gone, B is still open: the next letter is C. Handing
    # out A again here would put a second `voorstel A` next to the `voorstel B`
    # the operator is still looking at.
    store.redeem(first, "dienst_lid_uitschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    third = store.issue("certificaat_klaarzetten", {"certnaam": "ster2027"}, "lab", section=SECTION)
    assert store.marker(third) == "C"
    # Now nothing is outstanding, so the series starts again at A.
    store.redeem(second, "dienst_lid_inschakelen", {"dienst": "sg", "lid": "web01"}, "lab", section=SECTION)
    store.redeem(third, "certificaat_klaarzetten", {"certnaam": "ster2027"}, "lab", section=SECTION)
    fourth = store.issue("certificaat_klaarzetten", {"certnaam": "ster2027"}, "lab", section=SECTION)
    assert store.marker(fourth) == "A"


def test_an_expired_proposal_releases_its_letter():
    """The letter lives on the ENTRY, so the same sweep that drops an expired
    proposal frees its letter - no second bookkeeping that can drift."""
    store, clock = _store()
    first = store.issue("certificaat_klaarzetten", {"certnaam": "a"}, "lab", section=SECTION)
    assert store.marker(first) == "A"
    clock.t += TTL_S + 1
    second = store.issue("certificaat_klaarzetten", {"certnaam": "b"}, "lab", section=SECTION)
    assert store.marker(second) == "A"


def test_a_twenty_seventh_simultaneous_proposal_is_refused():
    """Design 3.7: more than 26 outstanding proposals does not exist. The
    refusal happens BEFORE a code is drawn, so a refused proposal leaves
    nothing behind that could still be redeemed."""
    store, _ = _store()
    codes = [
        store.issue("certificaat_klaarzetten", {"certnaam": f"cert{i}"}, "lab", section=SECTION) for i in range(26)
    ]
    assert len({store.marker(c) for c in codes}) == 26
    with pytest.raises(TooManyProposals):
        store.issue("certificaat_klaarzetten", {"certnaam": "cert26"}, "lab", section=SECTION)


def test_the_marker_of_an_unknown_code_is_refused_and_never_guessed():
    store, _ = _store()
    with pytest.raises(ConfirmError):
        store.marker("ZZZZZZ")


def test_the_marker_of_an_expired_proposal_is_refused_not_handed_out():
    """An earlier fix, corrected by a later one. The docstring promises the
    letter of an OUTSTANDING proposal. An entry past its ten minutes is not
    outstanding - `redeem()` already refuses it, and `marker()` must not
    hand back its letter either.

    The later fix changed WHICH refusal: `marker()` used to purge before looking up, so
    an expired entry was already gone by the time it could be classified and
    every refusal here read "onbekend of al gebruikt", indistinguishable
    from a code that never existed. `marker()` now reads the entry AS IT
    STANDS and reports "verlopen" for one that is present but past its
    `expires_at` - the SAME sentence `redeem()` gives that exact situation
    (see `test_marker_then_redeem_and_redeem_alone_agree_on_an_expired_proposal`
    below)."""
    store, clock = _store()
    code = store.issue("certificaat_klaarzetten", {"certnaam": "a"}, "lab", section=SECTION)
    clock.t += TTL_S + 1
    with pytest.raises(ConfirmError, match="verlopen"):
        store.marker(code)


def test_marker_then_redeem_and_redeem_alone_agree_on_an_expired_proposal():
    """The same fix, as a controller-resolution guard: a real guard, not
    a characterisation of a known trap: this drives BOTH call orders on a
    genuinely expired proposal, in the same store, and pins that they end in
    the SAME sentence - and that the sentence is "verlopen", never the
    generic "onbekend of al gebruikt".

    Before this fix, `marker()` purged the entry before looking it up, so a
    caller who read the letter first and redeemed second got "onbekend" for
    a code that had, in fact, simply expired - `redeem()`'s own
    pop-before-purge exists precisely to keep "verlopen" distinct from
    "onbekend" (see its comment), and reading the letter first threw that
    distinction away before `redeem()` ever ran. The fix closes this in the
    OWNER (`ConfirmationStore.marker()`): it no longer purges, so the entry
    is still there, still expired, for `redeem()` to find and classify
    exactly as it does when nobody called `marker()` first.
    """
    # Two SEPARATE stores, deliberately: `redeem()` sweeps the WHOLE store
    # after its pop, so a single shared store would let the first call order
    # silently purge the second code away before it is ever redeemed - a
    # test artefact, not the property under test. Each store isolates one
    # call order.
    tool, args, target = "certificaat_klaarzetten", {"certnaam": "a"}, "lab"

    marker_store, marker_clock = _store()
    marker_dan_redeem = marker_store.issue(tool, args, target, section=SECTION)
    marker_clock.t += TTL_S + 1
    with pytest.raises(ConfirmError, match="verlopen") as eerst:
        marker_store.marker(marker_dan_redeem)
    with pytest.raises(ConfirmError, match="verlopen") as daarna:
        marker_store.redeem(marker_dan_redeem, tool, args, target, section=SECTION)

    redeem_store, redeem_clock = _store()
    redeem_alleen = redeem_store.issue(tool, args, target, section=SECTION)
    redeem_clock.t += TTL_S + 1
    with pytest.raises(ConfirmError, match="verlopen") as alleen:
        redeem_store.redeem(redeem_alleen, tool, args, target, section=SECTION)

    assert str(eerst.value) == str(daarna.value) == str(alleen.value)
    assert "onbekend" not in str(alleen.value)


def test_expired_entries_are_purged_on_issue_and_on_redeem():
    """An expired code was refused (`redeem` checks
    the clock) but stayed in memory forever unless someone happened to
    present it. A server that runs for weeks then keeps every proposal that
    was never confirmed - a slow leak, and one a caller controls by simply
    asking for proposals. Both doors that touch the store sweep it now."""
    clock = {"t": 0.0}
    store = ConfirmationStore(now=lambda: clock["t"], ttl_s=600)

    _vergeten = store.issue("dienst_lid_uitschakelen", {"dienst": "a"}, "doel", section=SECTION)
    clock["t"] = 601.0
    # ISSUE sweeps: the forgotten code is gone from the store, not merely
    # unusable.
    vers = store.issue("dienst_lid_uitschakelen", {"dienst": "b"}, "doel", section=SECTION)
    assert list(store._pending) == [vers]

    clock["t"] = 700.0
    _tweede_vergeten = store.issue("dienst_lid_uitschakelen", {"dienst": "c"}, "doel", section=SECTION)
    clock["t"] = 1400.0
    derde = store.issue("dienst_lid_uitschakelen", {"dienst": "d"}, "doel", section=SECTION)
    assert list(store._pending) == [derde]

    # REDEEM sweeps too, and it does so without disturbing the code being
    # presented: the sweep may never spend the very code under judgement.
    clock["t"] = 1500.0
    vierde = store.issue("dienst_lid_uitschakelen", {"dienst": "e"}, "doel", section=SECTION)
    clock["t"] = 1600.0
    store.redeem(derde, "dienst_lid_uitschakelen", {"dienst": "d"}, "doel", section=SECTION)
    assert list(store._pending) == [vierde]

    # And an expired code still gets its OWN, honest refusal - the sweep
    # must not turn "verlopen" into "onbekend".
    zesde = store.issue("dienst_lid_uitschakelen", {"dienst": "f"}, "doel", section=SECTION)
    clock["t"] = 2300.0
    with pytest.raises(ConfirmError) as info:
        store.redeem(zesde, "dienst_lid_uitschakelen", {"dienst": "f"}, "doel", section=SECTION)
    assert "verlopen" in str(info.value)
    assert store._pending == {}


def test_a_code_is_burned_after_five_failed_attempts():
    store = ConfirmationStore()
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    with pytest.raises(ConfirmError) as exc:
        store.redeem(code, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert "onbekend of al gebruikt" in str(exc.value)


def test_a_code_still_works_after_four_failed_attempts():
    """The counter must not be so eager that a mistyped code costs the
    operator the whole proposal."""
    store = ConfirmationStore()
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(4):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    store.redeem(code, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)


def test_the_burn_notice_reaches_the_channel_and_carries_no_code():
    seen = []
    store = ConfirmationStore(on_burn=seen.append)
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert seen == [1]
    assert code not in "".join(str(item) for item in seen)


def test_a_burned_code_is_not_revived_by_a_retry_or_by_a_new_proposal():
    """The reset question, asked out loud. A lock that a guesser can lift by
    trying once more, or by asking the model for a fresh proposal, is not a
    lock."""
    store = ConfirmationStore()
    burned = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    # Retrying does not bring it back.
    for _ in range(3):
        with pytest.raises(ConfirmError) as exc:
            store.redeem(burned, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
        assert "onbekend of al gebruikt" in str(exc.value)
    # Nor does asking for a new proposal. A new proposal is the operator's
    # way forward and gets a counter of its own; it does not resurrect the
    # code that was guessed at.
    fresh = store.issue("certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)
    assert list(store._pending) == [fresh]
    store.redeem(fresh, "certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)


def test_a_successful_redeem_does_not_reset_the_counter_on_the_other_codes():
    """A guesser with a colleague who confirms something in the meantime is
    still a guesser: the count that was already on an outstanding code stays
    on it."""
    store = ConfirmationStore()
    guessed_at = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    other = store.issue("certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)
    for _ in range(4):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    store.redeem(other, "certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)
    with pytest.raises(ConfirmError):
        store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert store._pending == {}
    with pytest.raises(ConfirmError) as exc:
        store.redeem(guessed_at, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert "onbekend of al gebruikt" in str(exc.value)


def test_a_mismatched_code_does_not_count_against_the_other_proposals():
    """Documented in `_count_failure`: a mismatch answers for itself and its
    own entry is already gone. Counting it too would let one operator who
    retypes his arguments wrong burn a colleague's proposal."""
    store = ConfirmationStore()
    survivor = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        wrong_action = store.issue("dienst_lid_uitschakelen", {"dienst": "b"}, "doel", section=SECTION)
        with pytest.raises(ConfirmError) as exc:
            store.redeem(wrong_action, "dienst_lid_uitschakelen", {"dienst": "c"}, "doel", section=SECTION)
        assert "andere handeling of een ander doel" in str(exc.value)
    store.redeem(survivor, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)


def test_two_concurrent_attempts_on_one_code_cannot_both_pass():
    """`redeem` pops before it judges, so two threads presenting the same
    real code produce exactly one success. Measured rather than reasoned,
    because 'the lock cannot be raced' is the kind of claim that rots."""
    store = ConfirmationStore()
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    start = threading.Barrier(2, timeout=10)
    outcomes: list[str] = []
    guard = threading.Lock()

    def attempt() -> None:
        start.wait()
        try:
            store.redeem(code, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
            result = "ok"
        except ConfirmError:
            result = "geweigerd"
        with guard:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert [thread.is_alive() for thread in threads] == [False, False]
    assert sorted(outcomes) == ["geweigerd", "ok"]


def test_five_wrong_guesses_burn_the_pending_proposal_not_only_a_matching_code():
    """Design 3.6 unit 5, the binding test. A guessed code belongs to no issued
    code, so a counter per CODE only ever counts expired codes and fingerprint
    mismatches - and misses exactly the brute force that was measured (over a
    million redeem() calls per second). The counter therefore hangs on the
    FINGERPRINT of the attempt: the one thing a guesser has to get right for
    his guess to be worth anything."""
    store = ConfirmationStore()
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    with pytest.raises(ConfirmError) as exc:
        store.redeem(code, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert "onbekend of al gebruikt" in str(exc.value)


def test_guessing_at_one_proposal_never_burns_another():
    """The reason this is keyed rather than global: a guesser must not be able
    to kill the proposal the operator is about to confirm."""
    store = ConfirmationStore()
    victim = store.issue("dienst_lid_uitschakelen", {"dienst": "b"}, "doel", section=SECTION)
    for _ in range(8):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    store.redeem(victim, "dienst_lid_uitschakelen", {"dienst": "b"}, "doel", section=SECTION)


def test_guessing_at_one_target_never_burns_the_same_tool_elsewhere():
    """Neither test above pins the KEY: both give the victim a different tool
    than the guess, so a counter keyed on the tool alone - ignoring
    arguments and target entirely - would pass them too. Under that
    mutant, five guesses at your own certificaat_vervangen would still burn
    a colleague's certificaat_vervangen on a different target: the exact
    defect this counter exists to remove, merely narrowed to one tool. This
    test holds the tool fixed across attacker and victims and varies
    arguments and target instead, so it exercises both halves of the
    fingerprint the tool-only mutant would ignore.
    """
    store = ConfirmationStore()
    other_args = store.issue("certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)
    other_target = store.issue("certificaat_vervangen", {"dienst": "a"}, "ander-doel", section=SECTION)
    attacked = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    with pytest.raises(ConfirmError):  # the attacked one did burn
        store.redeem(attacked, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    store.redeem(other_args, "certificaat_vervangen", {"dienst": "b"}, "doel", section=SECTION)
    store.redeem(other_target, "certificaat_vervangen", {"dienst": "a"}, "ander-doel", section=SECTION)


def test_a_failing_burn_notice_never_swallows_the_refusal():
    """The notice is best effort; the refusal is not."""

    def explode(count: int) -> None:
        raise RuntimeError("het kanaal is stuk")

    store = ConfirmationStore(on_burn=explode)
    code = store.issue("certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    for _ in range(5):
        with pytest.raises(ConfirmError):
            store.redeem("ZZZZZZ", "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    with pytest.raises(ConfirmError) as exc:
        store.redeem(code, "certificaat_vervangen", {"dienst": "a"}, "doel", section=SECTION)
    assert "onbekend of al gebruikt" in str(exc.value)
