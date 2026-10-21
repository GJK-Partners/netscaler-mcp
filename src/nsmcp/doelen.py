"""Which targets this server knows: the answer of `status_doelen`.

The one reading answer about the CONFIGURATION rather than about the export.
Per target it says what an operator needs to pick the right `doel`: the name,
the address, how old the export of that target is, the last maintenance run in
the ledger, which writing tools the allowlist grants there, and whether an SSH
host key is pinned. Four sources, all on disk: the targets file, the
allowlist, the manifest of the one export and the ledger.

What it never says, by construction rather than by filtering afterwards: the
credential-target name and either fingerprint of a target (the answer reads
only `name`, `address` and whether a host key is PRESENT), and an allowlist
VALUE - an object name the operator granted - since only the tool NAMES of
the allowlist are read (`Allowlist.allows`).

The ledger is untrusted input, as everywhere else in this product: a run name
is shown only when it is a safe run name, a phase only when it is one of the
seven, and the state of that phase is this product's own word
(`upgrade.phase_state`), never the ledger's `uitkomst`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, _days_old, stamp_data
from nsmcp.handelen import WRITE_TOOLS, Allowlist
from nsmcp.upgrade import _read_moment, is_safe_run_name, latest_run_name, phase_state
from nsmcp.upgrade_plan import PHASE_NAMES

# The whole answer when there is no target at all: the same sentence
# `status_ververs` gives, one text for one fact.
GEEN_DOEL_TEXT = "Er is geen doel ingesteld; deze server antwoordt op een aangeleverde export."

DOELEN_QUESTION = "welke doelen kent deze server"
DOELEN_TELLING_EVIDENCE = "het doelenbestand en handelen.toegestaan in de configuratie"
DOEL_EVIDENCE = "het doelenbestand, handelen.toegestaan, het exportmanifest en het ledger"

ALLEEN_IN_ALLOWLIST_TEXT = "alleen in de allowlist, niet in het doelenbestand; geen adres"

GEEN_EXPORT_TEXT = "geen export in deze server"
GEEN_EXPORT_VAN_DIT_DOEL_TEXT = "geen export van dit doel in deze server (de export beschrijft een ander doel)"
EXPORT_ZONDER_DOEL_TEXT = (
    "niet vast te stellen of de export van dit doel is (de export zegt niet welk doel hij beschrijft)"
)

GEEN_LEDGER_TEXT = "geen ledger ingesteld (onderhoud staat niet in de configuratie)"
GEEN_ONDERHOUDSRUN_TEXT = "geen onderhoudsrun"
LEDGER_ONLEESBAAR_TEXT = "laatste onderhoudsrun niet vast te stellen: het ledger is niet leesbaar"
LEDGER_ONLEESBAAR_REASON = (
    "het ledger kon niet gelezen worden, dus de laatste onderhoudsrun van dit doel is niet vastgesteld"
)
LEDGER_ONLEESBAAR_GAP = (
    "het ledger kon niet gelezen worden; de laatste onderhoudsrun is voor geen enkel doel vast te stellen"
)
RUN_NAAM_NIET_GETOOND_TEXT = "laatste onderhoudsrun met een naam die geen veilige run-naam is; niet getoond"

NIET_AANGEMELD_PREFIX = "in de allowlist maar op deze server niet aangemeld: "


@dataclass(frozen=True)
class LedgerView:
    """What the ledger holds for the targets, read once per question.

    `configured` is False without an `onderhoud` section: there is no ledger
    to read, which is a different statement from an empty one. `unreadable`
    means the ledger directory (or a run file in it) could not be read at
    all - unknown, never "no run". `rows` carries per target its rows in time
    order; a target without an entry has none. `skipped` counts the lines
    that could not be read; a line cannot be attributed to a target, so it
    is one count for the whole ledger.
    """

    configured: bool
    unreadable: bool = False
    rows: Mapping[str, tuple] = field(default_factory=dict)
    skipped: int = 0


def target_names(targets: Mapping, allowlist: Allowlist) -> tuple[str, ...]:
    """Every target this server knows: the targets file and the allowlist
    sections together, each name once."""
    return tuple(sorted(set(targets) | set(allowlist.targets())))


def _export_part(name: str, export, today: date) -> str:
    """How old the export of THIS target is. There is one export per server,
    so for every other target the honest answer is that there is none."""
    if export.manifest_missing:
        return GEEN_EXPORT_TEXT
    if export.target_name is None or export.target_name_refused:
        return EXPORT_ZONDER_DOEL_TEXT
    if export.target_name != name:
        return GEEN_EXPORT_VAN_DIT_DOEL_TEXT
    # The same age the closing stamp of every answer states, from the same
    # function, so the two can never disagree.
    stamped = stamp_data(Answer(question=DOELEN_QUESTION), export.collected_at, today)
    if stamped.data_date is None or stamped.data_age_days is None:
        return f"export van dit doel zonder leesbare leeftijd: {stamped.data_age_reason}"
    return f"export van {stamped.data_date}, {_days_old(stamped.data_age_days)}"


def _last_row(rows) -> dict | None:
    """The row with the latest readable time; ties keep the later row, the
    same rule `latest_run_name` applies."""
    best, best_time = None, None
    for row in rows:
        if not isinstance(row, dict):
            continue
        moment = _read_moment(row.get("tijd"))
        if moment is None:
            continue
        if best_time is None or moment >= best_time:
            best, best_time = row, moment
    return best


def _run_part(rows) -> str:
    """The last maintenance run on this target, and its last line."""
    run = latest_run_name(rows)
    if not run:
        return GEEN_ONDERHOUDSRUN_TEXT
    if not is_safe_run_name(run):
        return RUN_NAAM_NIET_GETOOND_TEXT
    run_rows = tuple(row for row in rows if isinstance(row, dict) and row.get("run") == run)
    last = _last_row(run_rows)
    # `latest_run_name` only names a run that has a row with a readable time,
    # so `last` exists; the guard keeps an impossible case from crashing.
    if last is None:
        return f"laatste onderhoudsrun {run}"
    moment = _read_moment(last.get("tijd")).strftime("%Y-%m-%dT%H:%M:%SZ")
    fase = last.get("fase")
    if isinstance(fase, str) and fase in PHASE_NAMES:
        return f"laatste onderhoudsrun {run}, laatste regel {fase} {phase_state(run_rows, fase)} om {moment}"
    return f"laatste onderhoudsrun {run}, laatste regel zonder bekende fase om {moment}"


def _allowed_part(name: str, allowlist: Allowlist, offered: frozenset[str]) -> str:
    """Which writing tools the allowlist grants on this target - by tool NAME
    only - split into the ones this server offers and the ones it does not."""
    granted = [tool for tool in WRITE_TOOLS if allowlist.allows(name, tool)]
    usable = [tool for tool in granted if tool in offered]
    missing = [tool for tool in granted if tool not in offered]
    text = f"toegestaan: {', '.join(usable)}" if usable else "toegestaan: geen"
    if missing:
        text += f"; {NIET_AANGEMELD_PREFIX}{', '.join(missing)}"
    return text


def targets_answer(
    *,
    targets: Mapping,
    allowlist: Allowlist,
    offered: frozenset[str],
    export,
    ledger: LedgerView,
    today: date,
    knowledge,
) -> Answer:
    """The answer of `status_doelen`, before the closing stamps.

    `offered` is the set of writing tools THIS server registered: granted in
    the allowlist is not the same as callable, and the answer says which is
    which. The caller handles the case without any target (`GEEN_DOEL_TEXT`).
    """
    names = target_names(targets, allowlist)
    only_in_allowlist = [name for name in names if name not in targets]
    with_permission = [name for name in names if any(allowlist.allows(name, tool) for tool in WRITE_TOOLS)]
    telling = f"{len(targets)} in het doelenbestand, {len(with_permission)} met een toestemming in de allowlist"
    if only_in_allowlist:
        telling += f", {len(only_in_allowlist)} alleen in de allowlist"
    findings = [
        Finding(
            subject="doelen",
            outcome=telling,
            certainty=Certainty.ESTABLISHED,
            evidence=DOELEN_TELLING_EVIDENCE,
            subject_is_name=False,
            # A summary of the per-target lines below: at `minimaal` the
            # count of findings is the count of targets.
            counted_at_minimal=False,
        )
    ]
    for name in names:
        target = targets.get(name)
        parts = [f"adres {target.address}" if target is not None else ALLEEN_IN_ALLOWLIST_TEXT]
        parts.append(_export_part(name, export, today))
        if not ledger.configured:
            parts.append(GEEN_LEDGER_TEXT)
        elif ledger.unreadable:
            parts.append(LEDGER_ONLEESBAAR_TEXT)
        else:
            parts.append(_run_part(ledger.rows.get(name, ())))
        parts.append(_allowed_part(name, allowlist, offered))
        if target is not None:
            parts.append(f"hostsleutel gepind: {'ja' if target.ssh_hostsleutel_vingerafdruk else 'nee'}")
        findings.append(
            Finding(
                subject=name,
                outcome="; ".join(parts),
                certainty=Certainty.NOT_ESTABLISHED if ledger.unreadable else Certainty.ESTABLISHED,
                evidence=DOEL_EVIDENCE,
                reason=LEDGER_ONLEESBAAR_REASON if ledger.unreadable else "",
            )
        )
    read_gaps = []
    if ledger.unreadable:
        read_gaps.append(ReadGap(source="ledger", reason=LEDGER_ONLEESBAAR_GAP))
    elif ledger.skipped:
        read_gaps.append(
            ReadGap(
                source="ledger",
                reason=(
                    "1 ledgerregel kon niet gelezen worden"
                    if ledger.skipped == 1
                    else f"{ledger.skipped} ledgerregels konden niet gelezen worden"
                ),
            )
        )
    return Answer(
        question=DOELEN_QUESTION,
        findings=findings,
        read_gaps=read_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
