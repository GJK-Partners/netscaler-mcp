"""The three words a piece of reading advice may carry about itself.

A reading tool that says "replace this certificate" leaves an operator with
one more question: can this product do that, or do I do it by hand? The
answer is not a property of the advice but of the ADMINISTRATOR'S allowlist,
so it is computed from that list and never written by hand in an advice
text.

Three words and no fourth. Design 2.1.1 pins them; a fourth word would be a
change of that design, not of this module.

What the can-word promises depends on WHAT THE READING SIDE KNOWS. For an
argument whose value it knows - the virtual server an advice step names -
the word says: this product may perform this action on THIS object here. For
an argument whose value it does not know yet - the name of a certificate the
operator has not chosen - it says only: the administrator has approved at
least one object for this action on this target. That is weaker on purpose;
promising more about a name nobody has typed yet would be a promise about an
object that does not exist.
"""

from __future__ import annotations

from nsmcp.handelen import ActionError, Allowlist, validate

# The label of a step this product can carry out itself. Neutral wording, the
# same "dit product" the customer documents use: a product name in an
# answer would only date it.
ADVICE_CAN = "dit product kan dit uitvoeren"
ADVICE_NOT_ALLOWED = "niet in de allowlist"
ADVICE_MANUAL = "handmatige actie"
ADVICE_WORDS: tuple[str, ...] = (ADVICE_CAN, ADVICE_NOT_ALLOWED, ADVICE_MANUAL)


def _complete(
    tool: str, arguments: dict[str, str | None], *, target: str, allowlist: Allowlist
) -> dict[str, str] | None:
    """Fills every `None` with a value the ALLOWLIST ITSELF permits there.

    `None` says: the reading side does not know this value. Judging it is
    then impossible, and judging some OTHER name in its place - the one the
    caller happened to ask about - is what made the label answer about the
    wrong object. So the question becomes the one an allowlist can
    actually answer: has the administrator approved anything at all for this
    argument on this target? Substituting an approved value and running the
    normal `validate()` on the completed set asks exactly that, and keeps ONE
    decision path.

    Returns None when it cannot be completed - no object form for this tool
    on this target, or no approved value for the argument. The caller reads
    that as "niet in de allowlist", so an empty list stays a refusal, exactly
    as `Allowlist` intends its three spellings of "no".

    The substitute is the FIRST approved value, and it is not exempt from
    anything: `validate()` still runs the name grammar, the built-in denylist
    and the target check over it. A configuration whose first approved value
    that check refuses therefore yields the not-allowed word - fail closed,
    never the can-word.
    """
    entry = allowlist.entry(target, tool)
    completed: dict[str, str] = {}
    for field, value in arguments.items():
        if value is not None:
            completed[field] = value
            continue
        if not isinstance(entry, dict):
            return None
        approved = tuple(entry.get(field) or ())
        if not approved:
            return None
        completed[field] = approved[0]
    return completed


def advice_label(
    tool: str | None,
    arguments: dict[str, str | None],
    *,
    target: str | None,
    allowlist: Allowlist | None,
) -> str:
    """Which of the three words belongs to this advice item.

    `tool=None` means: this product has no writing tool for this step at all
    - a manual action, and that is a statement about the PRODUCT, not about
    the configuration.

    An argument VALUE of `None` means something else: the reading side does
    not know this value yet, because the operator has not chosen it. The
    accepted value domain is `str | None` for that reason - deliberately
    wider than a plain name, and this is the interface later modules inherit.
    Such an argument is not judged as a name; it is completed with a value
    the allowlist itself permits (see `_complete`), so the can-word then says
    the administrator has approved at least one object for this action on
    this target - not that this particular object is approved. Every argument
    the reading side DOES know keeps being judged exactly.

    Everything else is decided by the same `validate()` the writing path
    uses, so the label can never promise something the writing path would
    refuse for the arguments it actually judged. Fail closed: no allowlist,
    no target, a target the list does not know, and an argument the list
    approves nothing for all read as "niet in de allowlist".
    """
    if tool is None:
        return ADVICE_MANUAL
    if allowlist is None or not target:
        return ADVICE_NOT_ALLOWED
    completed = _complete(tool, arguments, target=target, allowlist=allowlist)
    if completed is None:
        return ADVICE_NOT_ALLOWED
    try:
        validate(tool, completed, target=target, allowlist=allowlist)
    except ActionError:
        return ADVICE_NOT_ALLOWED
    return ADVICE_CAN
