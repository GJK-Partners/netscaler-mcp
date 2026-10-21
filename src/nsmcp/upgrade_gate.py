"""`python -m nsmcp.upgrade_gate` - one phase in, one ledger line out.

The bridge between the two halves of the runner. The PowerShell script calls
this ONCE per phase with everything it measured, as one JSON object on stdin.
Back comes the ledger line it must append, on stdout, and an exit code that
says whether the phase succeeded. Nothing here talks to an appliance and
nothing here holds a secret: the measurements arrive already measured.

STDIN (one JSON object): `fase`, `run`, `doel`, `actieid`, `bevestiger`,
`gestart`, `geeindigd`, `ledger` (pad), `soak_uren`, and `metingen` - the
object `evaluate_phase()` receives as its `measurements`.

Two kinds of gate feed into the verdict, and only the FIRST kind is built
here:

- The ledger-derived gates - `order_gate()` (every phase) and `soak_gate()`
  (a run's FIRST phase, and R6) - because this module already has
  everything both need: the ledger itself and `soak_uren`. No measurement
  field name is invented for either. The soak gate is fed the lines for the
  TARGET (`doel`), across every run file in the same ledger directory, not
  only the current run's own file - the soak window binds the target, and
  that must include a next run's own first phase (`soak_gate`'s own
  docstring). Every ledger file this reads is UNTRUSTED input: a file that
  fails to parse contributes nothing rather than crashing this CLI, and
  neither the FILE NAMES in that directory nor the order `glob()` yields
  them decides which window binds (`_rows_for_target`, `_soak_opens`).
- The MEASUREMENT-derived gates (schijfruimte, secondary, vendor-precheck,
  firmware-hash, and whatever R0's own checks turn out to be) are each
  already a public function in `nsmcp.upgrade` (or a later task's own
  module) - the caller that actually knows the runner's stdin shape calls
  them and hands the results in through `metingen["poort"]`, in the SAME
  shape the ledger itself already uses (`naam`, `type`, `uitkomst`,
  `bewijs`, `reden` - see `ledger_line()`). This module does not guess a
  measurement field name of its own; it only merges gates that
  already arrived pre-judged.

Two things this module derives itself rather than trusting the script for:

- The ONE ceiling this module owns (`PHASE_LIMITS_S`) is measured here from
  `gestart`/`geeindigd`, ORed with whatever the script itself reported in
  `metingen["tijdslimiet_overschreden"]` - the script's own flag is never
  the only vote. A timestamp that cannot be READ is not "within the
  ceiling": it adds a `niet beoordeeld` time gate naming which timestamp
  failed, so the measuring half cannot switch the ceiling off by sending
  `"geeindigd": "n/a"` (`_duration_verdict`).
- The identity binding: a MISSING `actieid` or a missing
  `metingen["actieid_uit_script"]` is `mislukt`, same as a real mismatch -
  but it says the id ONTBREEKT rather than claiming a comparison that
  never happened. `evaluate_phase()`'s own bare `!=` comparison is
  plan-mandated and stays untouched; `None != None` is `False`, so the
  CLI's wiring closes that gap on top of it instead.

A phase that already carries a CLOSING row in its own run file is refused
outright (exit 2, nothing appended) rather than judged again: the ledger
allows exactly one closing line per phase, and re-judging a closed phase is
how a `poort dicht` gets silently overwritten by a later `geslaagd`.

STDOUT: the ledger line, as JSON - the exact object `append_line()` wrote.
Exit code: 0 for `geslaagd`, 1 for `poort dicht`, 2 for `mislukt` (and for
any input this module cannot make sense of - fail closed, never silently
0, and never exit 1 for a crash: exit 1 is this module's own word for a
JUDGED refusal, and a crash must never look like one; that is why the last
resort is `except Exception` and not a list of the exception types this
module happened to think of). This module writes the line itself with
`append_line()`: that is the one and only implementation of "append-only
and fsynced", so the script cannot route around it.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from nsmcp.bridge_io import read_stdin_text
from nsmcp.upgrade import (
    PHASE_LIMITS_S,
    Gate,
    PhaseVerdict,
    _bounded,
    _read_moment,
    append_line,
    evaluate_phase,
    ledger_line,
    order_gate,
    phase_has_closing_row,
    phase_state,
    read_ledger,
    soak_gate,
)
from nsmcp.upgrade_plan import PHASE_NAMES

_EXIT_CODES: dict[str, int] = {"geslaagd": 0, "poort dicht": 1, "mislukt": 2}

# design: "de ledger, letterlijk" - R0 and R6 each name their OWN closing
# `gebeurtenis` for a successful phase; every other phase closes with
# `fase_geslaagd`. Derived from `fase` alone - stdin carries no separate
# event field, so there is nothing here for a caller to get out of step
# with `verdict.outcome`.
_SUCCESS_EVENT: dict[str, str] = {"R0": "voormeting_vast", "R6": "soak_open"}

# The soak gate binds the run's FIRST phase (R0 today) as well as R6 - a
# next run's own R0 must be refused by a still-open window on the same
# target (soak_gate's own docstring).
_SOAK_CHECKED_PHASES: tuple[str, ...] = (PHASE_NAMES[0], "R6")

# The gate that reports this module's own ceiling when it cannot be judged.
_DURATION_GATE_NAME = "duur binnen tijdslimiet"

# The BACKSTOP ceiling on a gate that arrives through stdin. Set
# well above what any gate function in `nsmcp.upgrade` produces on its own,
# so a correctly bounded gate is never cut a SECOND time - re-cutting from
# the head would undo `_bounded_tail`'s whole point for R3, where the
# deciding `END_TIME` sits at the end. This is a cap on an unbounded caller,
# not a replacement for the per-gate bounding.
_POORT_ECHO_LIMIT = 1000


class ClosedPhaseError(ValueError):
    """A phase that already carries a closing row is refused, not re-judged.

    A `ValueError` subclass, so `main()`'s existing contract is unchanged,
    with its own type so `run()` can say what actually HAPPENED: this
    refusal is a judgement on perfectly readable input, and reporting it as
    "onleesbare invoer op stdin" describes the wrong failure to whoever is
    standing at the appliance.
    """


def _gates_from_measurements(metingen: dict) -> list[Gate]:
    """Poorten die de aanroeper al als oordeel aanlevert, in het ledger's
    eigen `poort`-vorm (naam/type/uitkomst/bewijs/reden).

    `naam`, `bewijs` en `reden` worden hier OPNIEUW
    begrensd. Alles wat via stdin binnenkomt is UNTRUSTED - ook wanneer het
    van `upgrade_measure` komt, want deze module heeft geen manier om dat te
    weten en is de laatste plek voor de ledgerregel. De poortfuncties in
    `nsmcp.upgrade` begrenzen aan hun kant al; dit is de tweede, en de enige
    die geldt voor een aanroeper die deze module rechtstreeks voedt."""
    ruw = metingen.get("poort") or []
    return [
        Gate(
            _bounded(p["naam"], 120),
            p["type"],
            p["uitkomst"],
            _bounded(p["bewijs"], _POORT_ECHO_LIMIT),
            _bounded(p.get("reden", ""), _POORT_ECHO_LIMIT),
        )
        for p in ruw
    ]


class LedgerUnreadable(RuntimeError):
    """The ledger DIRECTORY, or one of the run files in it, could not be read
    at all - so what it holds is unknown rather than absent.

    `_rows_for_target()` below answers "no rows"
    for both, and every caller that asks it a SAFETY question reads no rows
    as "nothing is open". Tolerable while the answer only shaped a soak
    message; not tolerable once it decides whether five other writing tools
    may touch an appliance that may still be mid-upgrade. A gate that cannot
    read its evidence must refuse, so the caller that needs that guarantee
    asks with `strict=True` and gets this instead of a silent empty tuple.

    What deliberately does NOT raise this: an unparseable or badly encoded
    LINE. `read_ledger()` skips those one by one, with a warning, and that
    tolerance stays exactly where it is - a single corrupt row must never
    brick a running upgrade.
    """


def _rows_from_file(pad, *, strict: bool = False, skipped: list | None = None) -> tuple[dict, ...]:
    """One ledger file's rows, or an empty tuple when the file does not
    (yet) exist or cannot be read - a brand new run's own file may not
    exist yet when its first phase is judged, and every ledger file this
    module reads is UNTRUSTED input: a file this CLI cannot make sense of
    must never crash it, only contribute nothing. `read_ledger()` handles a
    malformed or badly encoded LINE itself; what is caught here is a file
    that cannot be opened or read at all.

    `skipped`: passed straight through to `read_ledger()` (see there) so a
    caller that wants a per-line skip count across every file this scans
    can collect it in one list - not built here."""
    if not Path(pad).exists():
        return ()
    try:
        return read_ledger(pad, skipped=skipped)
    except (OSError, UnicodeDecodeError) as exc:
        if strict:
            raise LedgerUnreadable(
                f"een regelbestand in de ledgermap kon niet gelezen worden ({type(exc).__name__})"
            ) from None
        return ()


def _row_time(regel: dict) -> tuple[int, datetime]:
    """Sort key for a ledger row: its own `tijd`, in UTC. A row whose `tijd`
    cannot be read sorts LAST and keeps its relative position (`sorted` is
    stable) rather than being dropped."""
    moment = _read_moment(regel.get("tijd"))
    if moment is None:
        return 1, datetime.max.replace(tzinfo=UTC)
    return 0, moment


# Matches an IPv4 LITERAL only - four dot-separated groups of digits, and
# nothing else. Deliberately not a full IPv4 validator (an octet above 255
# still matches): this is a SHAPE test, so a domain strip is skipped for
# anything that looks like an address rather than a name, the same
# conservative spirit `scripts/README.md`'s own "verboden adressen" check
# documents for itself ("Not gedekt: ... een decimale of hexadecimale
# schrijfwijze").
_IPV4_SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _normalised_target(waarde) -> str:
    """A target's name in the one spelling this module compares on.

    `doel` used to be matched as an exact string, so the same appliance
    written as `lab-02` in one run file and `lab-02.lab.example`, ` LAB-02 `
    or `lab-02.` in another yielded "geen open soakvenster op dit doel" -
    indistinguishable from a genuinely fresh target, and that is the soak
    window silently not applying. Surrounding whitespace, capitalisation, a
    trailing dot and the domain part of an FQDN are not a different box.

    Comparing on the first label can only ever bind MORE rows to a target,
    never fewer: two different hosts that share a short name are then held
    to one window. That is the direction that REFUSES, which is the only
    direction this gate is allowed to err in.

    Carried defect, fixed here: that "first label" strip does not belong on
    an IPv4 LITERAL. `10.0.0.5` used to become `10` - not "the first label
    of a domain name" but the first OCTET of an address - so every appliance
    in `10/8` shared one soak window. Proven one-directional (it can only
    ever REFUSE a phase, never open a different target's window: a shared
    window only ever makes `soak_gate` say `dicht` more often), so this was
    correctness of the refusal message, not a security hole - but the
    message then named a start time from a DIFFERENT box without saying so.
    A dotted-quad is therefore compared whole, never split on its dots.
    """
    kaal = str(waarde or "").strip().strip(".").casefold()
    if _IPV4_SHAPE.match(kaal):
        return kaal
    return kaal.split(".", 1)[0]


def _rows_for_target(ledger_pad, doel, *, strict: bool = False, skipped: list | None = None) -> tuple[dict, ...]:
    """Every row naming `doel`, across every `*.jsonl` run file in the same
    ledger directory as `ledger_pad` - the soak window binds the TARGET,
    not one run's own file (`soak_gate`'s and `_soak_opens`' own
    docstrings: more than one `soak_open` line can exist across files, and
    the NEWEST is the one that binds). Every file is UNTRUSTED input; one
    that fails to parse simply contributes nothing.

    The rows come back in TIME order, on their own `tijd` field. A ledger
    directory was written by processes this module does not control, so the
    order `sorted(glob("*.jsonl"))` yields is not chronological order - a
    name that does not start with a digit sorts after every
    `<UTC>Z-<doel>.jsonl`. `_soak_opens` no longer depends on row order at
    all, and this ordering keeps any other consumer of these rows out of
    the same trap.

    `strict`: a directory that cannot be LISTED,
    or a run file that exists but cannot be READ, raises `LedgerUnreadable`
    instead of contributing nothing. Off by default - the soak path keeps
    the tolerance it has for a directory written by processes it does not
    control - and on for the caller that turns this answer into a
    single-writer guarantee, where "no rows" and "cannot tell" must not be
    the same answer. Per-LINE tolerance is untouched either way:
    `read_ledger()` still skips a corrupt row with a warning.

    `skipped`: forwarded to every `_rows_from_file()`
    call below, so a caller collects ONE list of skipped-line markers
    across every run file this target has, without touching the warnings
    module at all.
    """
    gezocht = _normalised_target(doel)
    ledgermap = Path(ledger_pad).parent
    # `Path.glob()` on a directory that does
    # not exist AT ALL returns an empty iterator - no `OSError`, unlike a
    # directory that exists but cannot be LISTED (permission denied, the
    # `except OSError` below). Left unchecked, a dropped network share or a
    # renamed ledger directory read as "nothing open" under `strict=True`
    # too - exactly the same answer as a genuinely empty target. Checked
    # BEFORE the glob, so this never depends on which of the two silent-vs-
    # raising shapes the filesystem happens to choose for a missing path.
    if strict and not ledgermap.is_dir():
        raise LedgerUnreadable(f"de ledgermap {ledgermap} bestaat niet (meer) of is geen map")
    try:
        bestanden = sorted(ledgermap.glob("*.jsonl"))
    except OSError as exc:
        if strict:
            raise LedgerUnreadable(f"de ledgermap kon niet gelezen worden ({type(exc).__name__})") from None
        return ()
    regels: list[dict] = []
    for bestand in bestanden:
        for regel in _rows_from_file(bestand, strict=strict, skipped=skipped):
            if isinstance(regel, dict) and _normalised_target(regel.get("doel")) == gezocht:
                regels.append(regel)
    return tuple(sorted(regels, key=_row_time))


def _duration_verdict(fase: str, gestart, geeindigd) -> tuple[bool, Gate | None]:
    """The one ceiling this module owns, derived from ITS OWN inputs:
    `(overschreden, poort)`.

    A non-zero `PHASE_LIMITS_S[fase]` is compared with the measured
    duration between `gestart` and `geeindigd`, and `main()` ORs the first
    return value with whatever the script itself reported - PHASE_LIMITS_S
    decides nothing if only the measuring half's own word is trusted.

    An UNREADABLE or absent timestamp is not "within the limit". Returning
    `False` for it silently switched this ceiling off, and the measuring
    half could do exactly that by sending `"geeindigd": "n/a"` - the one
    script-controlled ceiling, neutralised, with nothing in the evidence
    saying the duration could not be judged at all. It now yields a `niet
    beoordeeld` time gate naming the timestamp that failed; `niet
    beoordeeld` counts nowhere as `open` and nowhere as a pass, so the
    phase closes as `poort dicht` with the reason in the ledger. No timeout
    is manufactured that the measurements do not show.

    A phase whose limit is 0 (R0, R6) carries no ceiling and gets no gate.
    """
    limiet = PHASE_LIMITS_S.get(fase, 0)
    if limiet <= 0:
        return False, None
    begin = _read_moment(gestart)
    einde = _read_moment(geeindigd)
    if begin is None or einde is None:
        ontbrekend = "begintijd" if begin is None else "eindtijd"
        onleesbaar = gestart if begin is None else geeindigd
        return False, Gate(
            _DURATION_GATE_NAME,
            "tijd",
            "niet beoordeeld",
            f"fase {fase} kent een tijdslimiet van {limiet} s, maar de {ontbrekend} "
            f"is niet te lezen: {_bounded(onleesbaar, 60)!r}",
            f"de {ontbrekend} van deze fase is niet gelezen; de tijdslimiet is daarmee niet beoordeeld",
        )
    return (einde - begin).total_seconds() > limiet, None


def _identity_missing(actieid, metingen: dict) -> str:
    """Welke kant van de identiteitskoppeling ONTBREEKT, of `""`.

    `evaluate_phase()`'s bare `!=` vergelijking mist dit geval (`None !=
    None` is `False`), en dat is precies het moment waarop niets bevestigd
    is - de koppelingscontrole zou dan juist moeten weigeren, niet zwijgen.

    De tekst zegt `ontbreekt` en niet `komen niet overeen`: bij een
    ontbrekende kant is er geen vergelijking gemaakt, en het ledger hoort
    er ook geen te beweren.
    """
    zonder_bevestigd = not actieid
    zonder_script = not metingen.get("actieid_uit_script")
    if zonder_bevestigd and zonder_script:
        return "het actie-id ontbreekt aan beide kanten"
    if zonder_bevestigd:
        return "het actie-id van het bevestigde doel ontbreekt"
    if zonder_script:
        return "het actie-id in het ledger ontbreekt"
    return ""


def _build_context(
    fase: str,
    doel,
    actieid,
    metingen: dict,
    lines,
    ledger_pad,
    soak_uren,
    duurpoort: Gate | None = None,
    leesgat_poort: Gate | None = None,
) -> dict:
    gates = _gates_from_measurements(metingen)
    gates.append(order_gate(fase, lines))
    if duurpoort is not None:
        gates.append(duurpoort)
    if leesgat_poort is not None:
        gates.append(leesgat_poort)
    if fase in _SOAK_CHECKED_PHASES:
        target_lines = _rows_for_target(ledger_pad, doel) if ledger_pad else ()
        gates.append(_named_soak_gate(target_lines, datetime.now(UTC), soak_uren, doel))
    return {"actieid": actieid, "gates": tuple(gates)}


def _skipped_rows_gate(skipped: list) -> Gate:
    """A row in THIS run's own ledger
    file that could not be parsed is not nothing - it might have been a
    CLOSING row for this exact phase, unreadable and therefore invisible to
    `phase_has_closing_row()`. Without this gate, `main()` reads without
    `skipped` and a corrupt closing row makes the phase look `gestart` -
    which earns it a SECOND closing row, silently. `niet beoordeeld` here
    always drops the phase to `poort dicht` (`evaluate_phase()`'s own rule
    3: a `niet beoordeeld` gate never lets a phase close `geslaagd`), never
    `mislukt` and never `open` - the safest word for "the true closed state
    of this run cannot be fully established"."""
    regelnummers = ", ".join(str(n) for n in skipped)
    return Gate(
        "ledger leesbaar",
        "bewijs",
        "niet beoordeeld",
        f"regel(s) {_bounded(regelnummers, 200)} in het eigen ledgerbestand van deze run kon(den) niet gelezen worden",
        "een onleesbare regel in het eigen ledgerbestand van deze run kan zelf een sluitregel "
        "zijn geweest; de gesloten stand van deze fase is daardoor niet volledig vast te stellen",
    )


def _named_soak_gate(lines, now, soak_hours, doel) -> Gate:
    """`soak_gate()`, with the matched target named in its evidence.

    Carried defect, fixed alongside `_normalised_target` above: the gate
    itself only ever sees the rows `_rows_for_target` already filtered down
    to one target, and says nothing about WHICH target that was - so a
    refusal named an earliest end time without saying whose window it is.
    The gate's own vocabulary (`open`/`dicht`/`niet beoordeeld`, `reason`)
    is untouched; only `evidence` gains the matched name, via
    `dataclasses.replace` - never a second implementation of the gate
    itself.
    """
    gate = soak_gate(lines, now, soak_hours)
    return replace(gate, evidence=f"doel {_bounded(doel, 120)}: {gate.evidence}")


def _closing_event(fase: str, uitkomst: str) -> str:
    if uitkomst == "mislukt":
        return "fase_mislukt"
    if uitkomst == "poort dicht":
        return "poort_dicht"
    return _SUCCESS_EVENT.get(fase, "fase_geslaagd")


def main(stdin_text: str) -> tuple[dict, int]:
    """The whole bridge as one pure-ish call: parses `stdin_text`, judges,
    appends the ledger line, and returns `(regel, exitcode)`. Split out from
    `run()` so a caller (a future test) can exercise the judgement without
    piping through an actual OS process.

    Raises `ClosedPhaseError` (a `ValueError`) - caught by `run()` as exit
    2 - when `fase` already carries a closing row in its own run file: a
    closed phase is refused outright, never re-judged, and nothing is
    appended for it.

    That guard checks `phase_has_closing_row()`
    - ANY closing row for `fase` anywhere in `lines` - never `phase_state()`
    (the last row). The runner ALWAYS writes a fresh `fase_gestart` row
    before ever calling this module (`Invoke-GjkUpgradeFase.ps1`'s own step
    4), so on the real path the last row is, by construction, always that
    fresh start row - a `phase_state()`-based guard never once saw a closed
    phase as closed, even when an earlier closing row genuinely existed
    (`phase_has_closing_row()`'s own docstring). `skipped` is
    collected from THIS run's own file so a row that could not be parsed -
    which might have been exactly the closing row this guard is looking for
    - cannot be silently treated as "never happened": it becomes its own
    `niet beoordeeld` gate below, which keeps the phase from closing
    `geslaagd` on an unreadable history."""
    invoer = json.loads(stdin_text)
    fase = invoer["fase"]
    run = invoer["run"]
    doel = invoer["doel"]
    actieid = invoer.get("actieid")
    bevestiger = invoer.get("bevestiger")
    gestart = invoer.get("gestart")
    geeindigd = invoer.get("geeindigd")
    ledger_pad = invoer["ledger"]
    soak_uren = invoer.get("soak_uren")
    metingen = dict(invoer.get("metingen") or {})

    skipped: list = []
    lines = _rows_from_file(ledger_pad, skipped=skipped) if ledger_pad else ()
    if phase_has_closing_row(lines, fase):
        stand = phase_state(lines, fase)
        raise ClosedPhaseError(
            f"fase {_bounded(fase, 40)!r} staat al op '{stand}' in het ledger; "
            "een gesloten fase wordt niet opnieuw beoordeeld"
        )

    overschreden, duurpoort = _duration_verdict(fase, gestart, geeindigd)
    metingen["tijdslimiet_overschreden"] = bool(metingen.get("tijdslimiet_overschreden")) or overschreden

    leesgat_poort = _skipped_rows_gate(skipped) if skipped else None
    context = _build_context(fase, doel, actieid, metingen, lines, ledger_pad, soak_uren, duurpoort, leesgat_poort)
    context.update(run=run, doel=doel, gestart=gestart, poging=invoer.get("poging"), lines=lines)
    verdict = evaluate_phase(fase, metingen, context)
    ontbrekend = _identity_missing(actieid, metingen)
    if verdict.outcome != "mislukt" and ontbrekend:
        verdict = PhaseVerdict(
            fase,
            "mislukt",
            verdict.gates,
            f"fase {fase}: {ontbrekend}",
            f"{ontbrekend}; er is geen vergelijking gemaakt",
        )
    event = _closing_event(fase, verdict.outcome)

    regel = ledger_line(
        verdict,
        run=run,
        doel=doel,
        actieid=actieid,
        bevestiger=bevestiger,
        started=gestart,
        ended=geeindigd,
        event=event,
    )
    regel["poging"] = invoer.get("poging")
    append_line(ledger_pad, regel)
    return regel, _EXIT_CODES.get(verdict.outcome, 2)


def run() -> int:
    try:
        regel, exitcode = main(read_stdin_text())
    except ClosedPhaseError as fout:
        # Readable input, judged refusal - not the "unreadable stdin" every
        # other exit 2 reports.
        print(f"upgrade_gate: {_bounded(fout)}", file=sys.stderr)
        return 2
    except Exception as fout:
        # Deliberately EVERY exception and not a list of the ones this
        # module thought of: an enumerated tuple cannot keep the promise
        # above, and anything it misses leaves exit 1 - this module's own
        # word for `poort dicht` - standing for a crash. Measured: deeply
        # nested JSON on stdin raised RecursionError past the old tuple and
        # exited 1 with a traceback. No traceback is printed either; the
        # message is bounded because the exception text can carry untrusted
        # input.
        print(f"upgrade_gate: onleesbare invoer op stdin ({_bounded(fout)})", file=sys.stderr)
        return 2
    print(json.dumps(regel, ensure_ascii=False))
    return exitcode


if __name__ == "__main__":
    raise SystemExit(run())
