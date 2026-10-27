"""`python -m nsmcp.upgrade_measure` - the CLI ADAPTER two small bridges the
transport half (`scripts\\Invoke-GjkUpgradeFase.ps1`) calls ALONGSIDE `python -m
nsmcp.upgrade_gate`, not instead of it. `upgrade_gate.main()` is called exactly
once per phase and writes the ONE closing ledger row (design: this module never
touches that row and never calls `evaluate_phase()`); it merges gates from
`metingen["poort"]` as already-judged (`upgrade_gate._gates_from_measurements()`)
and never guesses a raw measurement field name itself - see that module's own
docstring: "the caller that actually knows the runner's stdin shape calls them
[the gate functions in `nsmcp.upgrade`] and hands the results in through
metingen['poort']". This module IS that caller's Python half: PowerShell knows
WHICH raw facts a phase measured, this module knows HOW to turn them into a
`Gate` by dispatching to the public, already-tested gate functions in
`nsmcp.upgrade` - `disk_gate`, `secondary_gate`, `hash_gate`, `precheck_gate`,
`hostkey_session_gate`, `presence_gate`, `anchor_evidence_gate`,
`backup_register_gate`, `build_tree_gate`, `export_age_gate`,
`family_counts_gate`, `floor_gate` (R0's target build against the current
build and the security floor), and `save_role_gate` for the save script of
`config_opslaan` (scripts/Invoke-GjkConfigOpslaan.ps1), which calls the same
`vorm` action for its role check.

These gate FUNCTIONS themselves moved to
`nsmcp.upgrade` - they belong with `Gate`, `GATE_TYPES` and `_bounded`, and
splitting them out here is what let one of them (`presence_gate`) skip
`_bounded` while its neighbour used it. This module re-exports them (`from
nsmcp.upgrade import ...`) so it stays what it should be: the CLI adapter
that reads stdin, does the file I/O a gate function itself never does
(reading the action register and an export directory are both FILE READS,
and file reads belong at the edge, not inside a pure gate function that a
unit test hands data to directly), and dispatches by `"soort"`/`"actie"`.

Actions, dispatched on stdin's own `"actie"` field:

- `"voorpoort"`: records required pre-write gates after this attempt's start,
  with an `open`/`dicht` permission outcome. It closes no phase; the runner
  performs a write only after the recorded outcome is `open`.
- `"precheck-pad"`: forms the safe result path bound to run, action and attempt.
- `"vorm"`: shapes a phase's raw measurements into the ledger's own `poort`
  form (`naam`/`type`/`uitkomst`/`bewijs`/`reden` - the same fields
  `nsmcp.upgrade.ledger_line()` writes) by routing each entry in
  `"verzoeken"` to the gate function its own `"soort"` names. STDOUT:
  `{"poort": [...]}`, in request order.
- `"start"`: writes the ONE `fase_gestart` marker row a run's first
  ledger entry for a phase always is (`onderhoud_upgrade_fase`, a later
  task, polls for exactly this row - `nsmcp.upgrade.wait_for_start()`).
  This is NOT a judgement - no gate is evaluated, no outcome is chosen; it
  is the same append-only, fsynced write `upgrade_gate.main()` itself uses
  (`nsmcp.upgrade.append_line()`), so PowerShell still never opens the
  ledger file itself and this module still never invents "append-only and
  fsynced" a second time (`upgrade.append_line`'s own docstring: it is the
  ONE implementation of that discipline). STDOUT: the written row, as JSON.
- `"terugrolpunt"`: writes R0's EXTRA `terugrolpunt_vast` evidence row
  (design 3.5 names TWO rows for R0), BEFORE `upgrade_gate` writes the
  closing `voormeting_vast` row. Same `append_line()`, no judgement, no
  phase closed - see `_terugrolpunt()` below. STDOUT: the written row.

Fail-closed, the same discipline as `upgrade_gate`: unreadable stdin, a
missing required field, or an unknown `"soort"`/`"actie"` is exit 2 - this
module never silently drops a requested gate or writes a malformed marker
row. Nothing here decides a phase outcome, nothing here writes a CLOSING
ledger row, and nothing here is the only path to `poort` - `upgrade_gate`
still merges whatever arrives in `metingen["poort"]` exactly as before,
whether that came from here or, for a future gate this module does not yet
know, from anywhere else the docstring already anticipates ("or a later
task's own module").

R0'S TWO SOURCES: R0 does NOTHING on the
appliance - its sources are the ACTION REGISTER (`"backupregister"`, a path
this module reads with `read_ledger()`, the same tolerant, per-line-fail-
closed JSONL reader the ledger itself uses - the action log is written the
same way, one JSON object per line) and the EXPORT (`"export-buildboom"`,
`"export-leeftijd"`, `"familietellingen"`, `"configuratie-anker-export"`, a
directory this module reads with `nsmcp.export.load_export()`). Both paths
are OPTIONAL on the request: an empty or unreadable path is `niet
beoordeeld`, never `open` and never a crash - see `_read_register_or_none`/
`_load_export_or_none` below. The runner's own parameters for these two
paths (`-Actieregister`, `-ExportRoot`) are wired in by the caller that
starts `Invoke-GjkUpgradeFase.ps1` (`build_upgrade_arguments()` in
`handelen.py`) - see `scripts/README.md`.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from nsmcp import localpath
from nsmcp.bridge_io import read_stdin_text
from nsmcp.export import load_export
from nsmcp.upgrade import (
    PRE_REQUIRED_GATES,
    SAVE_ROLE_GATE,
    Gate,
    _bounded,
    anchor_evidence_gate,
    append_line,
    backup_register_gate,
    blocking_phase,
    build_tree_gate,
    disk_gate,
    disk_read_gate,
    drift_live_gate,
    export_age_gate,
    family_counts_gate,
    floor_gate,
    hash_gate,
    # `hostkey_gate` is not dispatched by `_shape_one` below (the runner
    # feeds `hostkey_session_gate` instead - see that function's docstring),
    # but stays imported here so `upgrade_measure.hostkey_gate(...)` keeps
    # working for its own direct tests, unchanged by the move.
    hostkey_gate,  # noqa: F401 - re-exported, see comment above
    hostkey_session_gate,
    local_bundle_gate,
    order_gate,
    phase_has_closing_row,
    precheck_gate,
    precheck_path_gate,
    precheck_result_path,
    presence_gate,
    prior_write_gates,
    read_ledger,
    rollback_point_evidence,
    rollback_point_line,
    save_role_gate,
    secondary_gate,
    target_build_gate,
)
from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target

_EXIT_OK = 0
_EXIT_ONLEESBAAR = 2


class _OnleesbaarVerzoek(ValueError):
    """Stdin parsed as JSON but this module cannot make sense of it - an
    unknown `actie`/`soort`, or a required field missing. Caught by `run()`
    alone; never lets a request go unanswered rather than reporting exit 2."""


class _TweedeSchrijver(_OnleesbaarVerzoek):
    """Action `start` refused because the target already carries a phase
    that may still be running. The same exit 2 as an unreadable request -
    the runner turns ANY non-zero exit of `start` into its own [FOUT]/
    [GEWEIGERD] lines and stops before the transport - with its own words
    on stderr."""


def _refuse_a_second_writer(ledger, doel) -> None:
    """Defense in depth behind the server's own gates: the ONE writer of
    `fase_gestart` refuses when the ledger directory already carries, for
    this target, a phase that `blocking_phase()` still counts as open - a
    `fase_gestart` without a closing row, within that phase's time limit,
    of ANY run (the same rule, over the same rows, the server applies to
    every writing tool). A second runner therefore excludes itself even when
    the server missed the window - measured: a slow first runner wrote its
    row after the server's wait, and a second confirmed start went out
    behind it.

    The legitimate retries stay open: a phase with a closing row is not open,
    and one past its time limit counts as `mislukt` with reason
    `tijdslimiet`. A ledger directory that cannot be listed or a run file
    that cannot be read is "cannot tell", never "nothing open": refused as
    well (`strict=True`), the server's own discipline."""
    try:
        rows = _rows_for_target(ledger, doel, strict=True)
    except LedgerUnreadable as fout:
        raise _TweedeSchrijver(f"[GEWEIGERD] fase_gestart niet geschreven: {fout}") from None
    open_phase = blocking_phase(rows, datetime.now(UTC))
    if open_phase is not None:
        raise _TweedeSchrijver(
            "[GEWEIGERD] fase_gestart niet geschreven: er staat op dit doel al een fase open "
            f"(fase {open_phase.phase}, zonder sluitregel en binnen de tijdslimiet van "
            f"{open_phase.limit_s} s); een tweede faserunner op hetzelfde doel start niet"
        )


def _gate_dict(gate: Gate) -> dict:
    """One `Gate` in the ledger's own `poort` shape - the same four/five
    fields `nsmcp.upgrade.ledger_line()` writes, so a caller that puts this
    straight into `metingen["poort"]` needs no translation."""
    return {
        "naam": gate.name,
        "type": gate.type,
        "uitkomst": gate.outcome,
        "bewijs": gate.evidence,
        "reden": gate.reason,
    }


def _read_register_or_none(pad) -> list[dict] | None:
    """The action register at `pad`, as already-parsed rows, or `None` when
    no path was given or the file could not be read at all - the CALLER
    (`backup_register_gate`) turns `None` into an honest `niet beoordeeld`
    rather than a guessed `dicht`. Reuses `nsmcp.upgrade.read_ledger()`
    (the SAME tolerant, per-line JSONL reader the ledger itself uses)
    instead of a second parser, and every line it returns is just as
    UNTRUSTED as a ledger line is.

    THE WRITER is `mcp_server._act()` through `nsmcp.upgrade.register_line()`
    (since 8-9-2026): one row per EXECUTED write action, never for a
    proposal. The format read here is therefore a description of code
    that actually runs, not merely a stated contract: one JSON object per
    line, carrying at least `tool`, `doel`, `uitkomst`, `actieid` and - for
    `onderhoud_backup_maken` - `nsmcp.upgrade.REGISTER_OBJECT_FIELD` with
    the backup name the product formed. When `onderhoud.actieregister` is
    not configured, every real path here reads nothing and every gate that
    depends on it is `niet beoordeeld` - it fails closed, so there is no
    verdict hole."""
    tekst = str(pad or "").strip()
    if not tekst:
        return None
    # 1.1 B: one `localpath` walk (`read_ledger`); a missing register, a
    # refusal (a link in its place) and an unreadable one are all None:
    # `backupobject aanwezig` is then `niet beoordeeld`.
    try:
        return list(read_ledger(tekst))
    except OSError:
        return None


def _load_export_or_none(pad):
    """The export at `pad` as an `nsmcp.export.Export`, or `None` when no
    path was given or the directory could not even be opened. A path that
    DOES open but carries no manifest, or no manifest for the resource a
    gate needs, is NOT `None` here - `load_export()`/`Export.objects()`
    already turn that into a `ReadGap` on their own, honest `niet
    beoordeeld` machinery; this function only guards the "nothing to open
    at all" case so a gate function never has to special-case an empty
    string."""
    tekst = str(pad or "").strip()
    if not tekst:
        return None
    directory = Path(tekst)
    # 1.1 B: through the walk, no `exists()` by name.
    try:
        if localpath.exists_local(directory) is None:
            return None
    except OSError:
        return None
    try:
        return load_export(directory)
    except OSError:
        return None


def _vereist(verzoek: dict, veld: str):
    if veld not in verzoek:
        raise _OnleesbaarVerzoek(f"verzoek van soort {verzoek.get('soort')!r} mist het veld {veld!r}")
    return verzoek[veld]


def _shape_one(verzoek: dict) -> Gate:
    if not isinstance(verzoek, dict):
        raise _OnleesbaarVerzoek("elk verzoek moet een object zijn")
    soort = verzoek.get("soort")
    if soort == "schijfruimte-live":
        # `bundel_al_aanwezig` - waar is (R1's
        # upload-skip) - laat disk_gate de gemeten bundelgrootte als
        # een BEWUSTE nul lezen, nooit als ongemeten.
        return disk_read_gate(
            verzoek.get("vrij_mb"),
            verzoek.get("bundel_mb"),
            verzoek.get("uitpak_mb"),
            verzoek.get("exitcode"),
            verzoek.get("stderr", ""),
            bundle_present=verzoek.get("bundel_al_aanwezig") is True,
        )
    if soort == "schijfruimte":
        return disk_gate(
            verzoek.get("vrij_mb"),
            verzoek.get("bundel_mb"),
            verzoek.get("uitpak_mb"),
            bundle_present=verzoek.get("bundel_al_aanwezig") is True,
        )
    if soort == "secondary":
        # A live role reading requires command success and the configured NSIP.
        status = verzoek.get("exitcode")
        if type(status) is not int or status != 0 or not verzoek.get("doel_adres"):
            return Gate(
                "doel is secondary",
                "bewijs",
                "niet beoordeeld",
                f"show ha node: exitcode={status!r}; stderr={_bounded(verzoek.get('stderr', ''))}",
                "geen geslaagde HA-lezing met het doeladres",
            )
        gate = secondary_gate(
            verzoek.get("ha_node_uitvoer"),
            verzoek.get("doel_adres"),
            standalone_accepted=(verzoek.get("standalone_geaccepteerd") is True),
        )
        return Gate(
            gate.name,
            gate.type,
            gate.outcome,
            gate.evidence + "; exitcode=0; doeladres=" + _bounded(verzoek["doel_adres"]),
            gate.reason,
        )
    if soort == "configstand":
        # R1's drift gate, measured live: `show ns config` in R1's own
        # pre-write session. The acceptance counts only as a real JSON true.
        return drift_live_gate(
            verzoek.get("uitvoer"),
            verzoek.get("exitcode"),
            drift_geaccepteerd=verzoek.get("drift_geaccepteerd") is True,
        )
    if soort == "rol-voor-opslaan":
        # config_opslaan's role check (scripts/Invoke-GjkConfigOpslaan.ps1):
        # the same command-success and target-address rule as 'secondary'
        # above, then the stricter save_role_gate. Only 'open' lets the
        # script save.
        status = verzoek.get("exitcode")
        if type(status) is not int or status != 0 or not verzoek.get("doel_adres"):
            return Gate(
                SAVE_ROLE_GATE,
                "bewijs",
                "niet beoordeeld",
                f"show ha node: exitcode={status!r}; stderr={_bounded(verzoek.get('stderr', ''))}",
                "geen geslaagde HA-lezing met het doeladres; er wordt niet opgeslagen",
            )
        gate = save_role_gate(verzoek.get("ha_node_uitvoer"), verzoek.get("doel_adres"))
        return Gate(
            gate.name,
            gate.type,
            gate.outcome,
            gate.evidence + "; exitcode=0; doeladres=" + _bounded(verzoek["doel_adres"]),
            gate.reason,
        )
    if soort == "doelbuild-vloer":
        # R0: the target build against the current build and the security
        # floor. The server read the current build from the export and
        # computed the floor; a request without the `huidig` field is not
        # assessed (never "not known"); the acceptance counts only as a real
        # JSON true. The package the floor came from is named in the
        # evidence, with its age against today as R0 runs.
        return floor_gate(
            verzoek.get("doelbuild"),
            verzoek.get("vloer"),
            verzoek.get("bulletin"),
            verzoek.get("geaccepteerd") is True,
            huidig=verzoek.get("huidig"),
            pakket=verzoek.get("pakket"),
            pakket_datum=verzoek.get("pakket_datum"),
            vandaag=datetime.now(UTC).date(),
        )
    if soort == "doelbuild":
        return target_build_gate(
            verzoek.get("versie_uitvoer"), verzoek.get("doelbuild"), verzoek.get("exitcode"), verzoek.get("stderr", "")
        )
    if soort == "lokale-bundel":
        return local_bundle_gate(verzoek.get("vendor_sha"), verzoek.get("lokale_sha"))
    if soort == "firmware-hash":
        return hash_gate(verzoek.get("vendor_sha"), verzoek.get("doos_sha"))
    if soort == "precheck-pad":
        return precheck_path_gate(verzoek.get("pad"), verzoek.get("exitcode"), verzoek.get("stdout"))
    if soort == "precheck-poging":
        if type(verzoek.get("exitcode")) is not int or verzoek.get("exitcode") != 0:
            return Gate(
                "vendor-precheck",
                "bewijs",
                "niet beoordeeld",
                f"resultaatpad={_bounded(verzoek.get('pad'))}; leesexitcode={verzoek.get('exitcode')!r}",
                "het resultaatbestand van deze poging is niet geslaagd gelezen",
            )
        gate = precheck_gate(verzoek.get("precheck_json"))
        return Gate(
            gate.name,
            gate.type,
            gate.outcome,
            gate.evidence + "; resultaatpad=" + _bounded(verzoek.get("pad")),
            gate.reason,
        )
    if soort == "vendor-precheck":
        return precheck_gate(verzoek.get("precheck_json"))
    if soort == "hostsleutel":
        # Het echte gemeten feit is niet "gemeten
        # == verwacht" (dat vergelijkt PowerShell nooit onafhankelijk - zie
        # hostkey_session_gate's eigen docstring), maar OF de sessie is
        # geopend, en zo niet, OF dat specifiek een hostsleutelfout was.
        # `gepinde_vingerafdruk`: GEEN pin is `dicht`,
        # niet `niet beoordeeld` - een afwezige pin is een vastgestelde
        # afwezigheid en dus een weigering. Ontbreekt het veld, dan is de
        # lege standaard fail-closed.
        return hostkey_session_gate(
            bool(verzoek.get("sessie_geopend")),
            bool(verzoek.get("hostsleutelfout")),
            str(verzoek.get("foutmelding", "")),
            str(verzoek.get("gepinde_vingerafdruk", "")),
        )
    if soort == "configuratie-anker":
        status = verzoek.get("exitcode")
        if type(status) is not int or status != 0:
            return Gate(
                "configuratie-anker",
                "bewijs",
                "niet beoordeeld",
                f"show ns runningConfig: exitcode={status!r}; stderr={_bounded(verzoek.get('stderr', ''))}",
                "de configuratie is niet aantoonbaar geslaagd gelezen",
            )
        regels = verzoek.get("regels")
        if not isinstance(regels, list) or any(not isinstance(r, str) for r in regels):
            return Gate(
                "configuratie-anker",
                "bewijs",
                "niet beoordeeld",
                "show ns runningConfig: exitcode=0; stdout ontbreekt of heeft verkeerde vorm",
                "de configuratie is niet leesbaar",
            )
        gate = anchor_evidence_gate(regels)
        return Gate(
            gate.name,
            gate.type,
            gate.outcome,
            gate.evidence
            + (
                "; show ns runningConfig: exitcode=0, leeg gelezen"
                if not any(regels)
                else "; show ns runningConfig: exitcode=0"
            ),
            gate.reason,
        )
    if soort == "aanwezig":
        # `bewijs_kant`: 'staart' voor de ene
        # aanroeper wiens beslissende feit ACHTERAAN staat (R3's installns,
        # waar END_TIME de laatste regel is). Standaard 'kop', zoals altijd.
        return presence_gate(
            _vereist(verzoek, "naam"),
            _vereist(verzoek, "poorttype"),
            verzoek.get("aanwezig"),
            str(verzoek.get("bewijs", "")),
            str(verzoek.get("reden_dicht", "")) or "niet aangetoond",
            str(verzoek.get("bewijs_kant") or "kop"),
        )
    if soort == "backupregister":
        # R0's backupobject-gate bron is het
        # ACTIEREGISTER, nooit de appliance.
        regels = _read_register_or_none(verzoek.get("pad"))
        return backup_register_gate(regels, verzoek.get("doel"))
    if soort == "export-buildboom":
        export = _load_export_or_none(verzoek.get("export_root"))
        return build_tree_gate(export)
    if soort == "export-leeftijd":
        export = _load_export_or_none(verzoek.get("export_root"))
        return export_age_gate(export)
    if soort == "familietellingen":
        export = _load_export_or_none(verzoek.get("export_root"))
        return family_counts_gate(export)
    if soort == "configuratie-anker-export":
        # R0's export-gebonden route naar dezelfde 'configuratie-anker'-poort
        # als R5's live-SSH-route hierboven ('configuratie-anker') - zelfde
        # poortnaam, andere bron, en fail-closed op de bron zelf voordat
        # anchor_evidence_gate ooit een lege lijst als "gemeten" krijgt.
        export = _load_export_or_none(verzoek.get("export_root"))
        if export is None:
            return Gate(
                "configuratie-anker",
                "bewijs",
                "niet beoordeeld",
                "geen exportpad meegegeven",
                "het configuratie-anker is niet gelezen: geen export beschikbaar",
            )
        regels, gap = export.running_config_lines()
        if gap is not None:
            return Gate("configuratie-anker", "bewijs", "niet beoordeeld", str(gap.reason)[:200], str(gap.reason)[:200])
        return anchor_evidence_gate(regels)
    raise _OnleesbaarVerzoek(f"onbekende soort: {soort!r}")


def _vorm(invoer: dict) -> dict:
    verzoeken = invoer.get("verzoeken") or []
    if not isinstance(verzoeken, list):
        raise _OnleesbaarVerzoek("'verzoeken' moet een lijst zijn")
    return {"poort": [_gate_dict(_shape_one(v)) for v in verzoeken]}


def _start(invoer: dict) -> dict:
    for veld in ("run", "doel", "fase", "ledger"):
        _vereist(invoer, veld)
    _refuse_a_second_writer(invoer["ledger"], invoer["doel"])
    regel = {
        "tijd": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "run": invoer["run"],
        "doel": invoer["doel"],
        "fase": invoer["fase"],
        "gebeurtenis": "fase_gestart",
        "poort": [],
        "uitkomst": "gestart",
        "bewijs": "",
        "actieid": invoer.get("actieid"),
        "bevestiger": invoer.get("bevestiger"),
        "gestart": invoer.get("gestart"),
        "poging": invoer.get("poging"),
        "geeindigd": None,
        # The target build this phase started with: R1..R6 compare the
        # current bundle with R0's (`upgrade.run_binding_refusal`), which
        # checks this field on form when it reads it back.
        "doelbuild": invoer.get("doelbuild") if isinstance(invoer.get("doelbuild"), str) else None,
    }
    append_line(invoer["ledger"], regel)
    return regel


def _voorpoort(invoer: dict) -> dict:
    for key in ("run", "doel", "fase", "ledger", "actieid", "poging", "gestart"):
        if not _vereist(invoer, key):
            raise _OnleesbaarVerzoek(f"voorpoort mist {key}")
    phase = invoer["fase"]
    if phase not in PRE_REQUIRED_GATES:
        raise _OnleesbaarVerzoek("voorpoort is alleen voor een schrijffase")
    skipped = []
    rows = list(read_ledger(invoer["ledger"], skipped=skipped))
    rows = [r for r in rows if r.get("run") == invoer["run"] and r.get("doel") == invoer["doel"]]
    if phase_has_closing_row(rows, phase):
        raise _OnleesbaarVerzoek("deze fase is al gesloten")
    gates = _vorm(invoer)["poort"]
    gates.append(_gate_dict(order_gate(phase, rows)))
    if skipped:
        gates.append(
            _gate_dict(
                Gate(
                    "ledger leesbaar",
                    "bewijs",
                    "niet beoordeeld",
                    "onleesbare regels in het eigen ledger",
                    "de voorafgaande fasestand is niet volledig leesbaar",
                )
            )
        )
    row = {key: invoer[key] for key in ("run", "doel", "fase", "actieid", "poging", "gestart")}
    row.update(
        tijd=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        gebeurtenis="voorpoort",
        poort=gates,
        uitkomst="open",
        bewijs="voorpoort voor de schrijfactie",
        bevestiger=invoer.get("bevestiger"),
        geeindigd=None,
    )
    context = dict(invoer, lines=[*rows, row])
    verified = prior_write_gates(phase, context)
    if not verified or any(g.outcome != "open" for g in verified):
        row["uitkomst"] = "dicht"
        if not gates or verified[0].outcome == "niet beoordeeld":
            row["poort"].insert(0, _gate_dict(verified[0]))
    append_line(invoer["ledger"], row)
    return row


def _terugrolpunt(invoer: dict) -> dict:
    """R0's EXTRA `terugrolpunt_vast` evidence row - written BEFORE the
    closing `voormeting_vast` row, through the same single `append_line()`
    path every other ledger row uses.

    This module does the FILE I/O (the action register, the export
    directory) and `nsmcp.upgrade.rollback_point_evidence()` does the
    reading and the wording - the same split as every gate here. No
    judgement is made and no phase is closed: `uitkomst` stays `gestart`
    and `gebeurtenis` is deliberately absent from `_CLOSING_EVENTS`, so
    "exactly one `fase_gestart` and one closing row per phase" holds
    unchanged with this row sitting between them.

    The gates handed in through `poort` are the ones the caller ALREADY had
    shaped for this phase (action `vorm`); they are echoed, not re-judged,
    so the evidence row and the closing row can never disagree about what
    R0 measured."""
    for veld in ("run", "doel", "ledger"):
        _vereist(invoer, veld)
    regels = _read_register_or_none(invoer.get("actieregister"))
    export = _load_export_or_none(invoer.get("export_root"))
    bewijs = rollback_point_evidence(
        regels,
        export,
        invoer.get("snapshotverwijzing"),
        invoer["doel"],
    )
    ruwe_poorten = invoer.get("poort") or []
    if not isinstance(ruwe_poorten, list):
        raise _OnleesbaarVerzoek("'poort' moet een lijst zijn")
    # Re-bounded here, on the way OUT of this
    # module - the identical construction in
    # `upgrade_gate._gates_from_measurements()` already does this, for the
    # same reason that one gives: everything on stdin is UNTRUSTED, even
    # when it came from a caller that already bounded its own side (this
    # module cannot know that), and this row travels into the ledger the
    # same as `upgrade_gate`'s does. `1000` mirrors that function's own
    # backstop (`upgrade_gate._POORT_ECHO_LIMIT`) rather than the plainer
    # `_bounded()` default (200): well above what any gate function here
    # produces on its own, so a correctly bounded gate is never cut a
    # second time.
    gates = [
        Gate(
            _bounded(p["naam"], 120),
            p["type"],
            p["uitkomst"],
            _bounded(p["bewijs"], 1000),
            _bounded(p.get("reden", ""), 1000),
        )
        for p in ruwe_poorten
    ]
    regel = rollback_point_line(
        gates,
        bewijs,
        run=invoer["run"],
        doel=invoer["doel"],
        actieid=invoer.get("actieid"),
        bevestiger=invoer.get("bevestiger"),
        started=invoer.get("gestart"),
    )
    append_line(invoer["ledger"], regel)
    return regel


def main(stdin_text: str) -> tuple[dict, int]:
    """Parses `stdin_text`, dispatches on `"actie"`, and returns `(uitvoer,
    exitcode)` - split from `run()` so a test can exercise this without a
    real OS process, the same shape as `upgrade_gate.main()`."""
    invoer = json.loads(stdin_text)
    actie = invoer.get("actie")
    if actie == "vorm":
        return _vorm(invoer), _EXIT_OK
    if actie == "precheck-pad":
        return {"pad": precheck_result_path(invoer.get("run"), invoer.get("actieid"), invoer.get("poging"))}, _EXIT_OK
    if actie == "voorpoort":
        return _voorpoort(invoer), _EXIT_OK
    if actie == "start":
        return _start(invoer), _EXIT_OK
    if actie == "terugrolpunt":
        return _terugrolpunt(invoer), _EXIT_OK
    raise _OnleesbaarVerzoek(f"onbekende actie: {actie!r}")


def run() -> int:
    try:
        uitvoer, code = main(read_stdin_text())
    except _OnleesbaarVerzoek as fout:
        print(f"upgrade_measure: {fout}", file=sys.stderr)
        return _EXIT_ONLEESBAAR
    except Exception as fout:
        # Same discipline as `upgrade_gate.run()`: deliberately every
        # exception, so a crash never looks like a judged 0 and the
        # traceback (which can carry untrusted appliance text) is never
        # printed raw.
        print(f"upgrade_measure: onleesbare invoer op stdin ({fout})", file=sys.stderr)
        return _EXIT_ONLEESBAAR
    print(json.dumps(uitvoer, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(run())
