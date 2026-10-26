"""The MCP front door: up to thirty-four tools. Twenty-seven READ - twenty-five are
offline; `status_ververs` and `status_update_preflight` may refresh a scan. The other seven WRITE, each
through the same proposal-and-confirmation-code path (`_act`), and they
exist only when a `handelen` section is configured AND the disclosure
setting is 'volledig' or 'beperkt' - refused only at 'minimaal' - see the
gate above their registration.

This used to say "sixteen
tools... Eleven READ... five WRITE" - true before
`onderhoud_upgrade_fase` (the sixth WRITE tool) and
`onderhoud_upgrade_stand`/`rapport_na_upgrade` (the twelfth
and thirteenth READ tools) were added. "Up to" nineteen because the six WRITE tools
and two of the thirteen READ tools (`onderhoud_upgrade_stand`,
`rapport_na_upgrade`) register only when `onderhoud`/`handelen` are
configured; the count is pinned at its full nineteen in
`tests/test_product_surface.py::test_full_tool_surface_with_handelen_
matches_the_nineteen_pinned_tools`.

Deliberately no computation in this file - not even `status_ververs`
computes anything itself, it delegates to collect.collect(), and the
writing tools delegate to the reviewed PowerShell write script through
handelen.perform(). The model gets no
configuration in its context, with three exceptions: an unknown target name
is answered with the list of configured target names (at 'volledig' only),
every answer carries the configured target name in its provenance line
("doel: <naam>", or "niet vastgelegd" when the export cannot prove it - see
`stamp_data` in answer.py), and `status_doelen` names every configured
target with its address and the NAMES of the writing tools granted there -
never a credential target, a fingerprint or an allowlisted object name (see
doelen.py).

Three security measures guard this front door (review history and the
measurements behind them: the regression coverage below):

1. Identity pinning. The MCP SDK accepts a second initialize on a live
   session and overwrites the client identity unconditionally; there is no
   SDK hook on the handshake. `_secure_identity` therefore pins the first
   identity seen per session, read via the Context of every tool call -
   after a re-initialize no tool call succeeds without contradicting the
   pinned identity.
2. Argument-validation masking. fastmcp validates arguments BEFORE the
   tool function (and thus our guard) runs, and a bare pydantic message
   leaks internal argument-model names. `_mask_argument_validation(server)`
   wraps the per-instance `fn_metadata` of the tools of THIS server only -
   deliberately not the shared class, so other FastMCP servers in the same
   process keep their own error behavior.
3. Client-name hygiene. The client name is free self-declaration;
   `clean_client_name` refuses borrowed authority names (`_DENIED`) and
   path/URL shapes before they enter the evidence chain.

`IdentitySwitched`, `InvalidClientName` and `Refusal` (permissions.py)
are `ToolError` subclasses: intended refusals whose text passes
through `mask_error()` unchanged; every other exception is replaced by
one fixed Dutch message.

`_decide()` is the single decision point (pin identity, then apply the
permissions decision); `_guarded()` (sync, the nine remaining answering
tools) and `_guarded_async()` (status_ververs, status_update_preflight
and the seven writing tools) both call it, and share
`_mask_if_needed()` for masking - what remains between the two is
exactly what Python's syntax requires: `work()` versus `await work()`.

`status_ververs`, `status_update_preflight` and the seven writing tools
are async: the scan and the write script both run via
`asyncio.to_thread(...)` so the event loop keeps serving other calls, and
cancellation is honored for the scan up to the commit boundary of the
export swap; a write already handed to the script runs to completion (the
caller sees CancelledError while the change lands). See
the `SwapGate` class (collect.py) for the gate contract and the
inline comments in `status_ververs` below for the cancellation path.

What masking does NOT promise: `_scrub_error_text` (collect.py) masks
the three KNOWN values of the called target (address, credential target
name, fingerprint) in a failed-scan report, but the stderr tail may still
contain values this product does not know as "of the target". That tail
therefore reaches the answer only at openheid 'volledig': below it,
`status_ververs` swaps it for one fixed phrase
(`CollectError.without_script_output()`, collect.py) - the same rule the
writing tools' registration gate follows for the same kind of text. See
docs/klant/SECURITY.md for the customer-facing statement of that boundary.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import weakref
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP

from nsmcp import __version__
from nsmcp.action import (
    REPLACED_CERTIFICATE_SUBJECT,
    USE_NOT_ESTABLISHED_OUTCOME,
    replacement_findings,
    what_to_do,
)
from nsmcp.after_upgrade import report_after_upgrade
from nsmcp.answer import Answer, Certainty, Finding, ReadGap, knowledge_age_line, safe_name, safe_text, stamp_data
from nsmcp.backup import readback_ok, save_readback_ok
from nsmcp.chain import service_chain
from nsmcp.code_channel import BURN_NOTICE, CHANNEL_FAILED, OLD_PRESENTER_MARKER, MirrorRefused, send_notice
from nsmcp.collect import (
    CollectError,
    SwapGate,
    _scrub_error_text,
    collect,
    phase_report,
    phase_summary,
    read_single_resource,
)
from nsmcp.compare import MODES as COMPARE_MODES, compare_answer, two_newest
from nsmcp.config_drift import drift_answer
from nsmcp.confirm import TTL_S, ConfirmationStore, ConfirmError, marker_line
from nsmcp.coverage import coverage_answer
from nsmcp.cve import cve_check
from nsmcp.dienst import service_status
from nsmcp.disclosure import (
    _UNKNOWN_NAME_IN_QUESTION,
    Disclosure,
    has_pseudonym_shape,
    names_from_export,
    render,
    resolve_pseudonym,
)
from nsmcp.doelen import GEEN_DOEL_TEXT, LedgerView, target_names, targets_answer
from nsmcp.errors import ToolError
from nsmcp.expiry import what_expires
from nsmcp.export import collected_at_some_point, collected_for, load_export, plain_path, record_provenance
from nsmcp.ha import DRIFT_LABEL, UNCONFIRMED, _drift_dimension, ha_state

# `_marker` (leading underscore, same module family) - reused rather than
# reimplemented for the SAME reason `_rows_for_target` above is: it is
# already the one place that reads a `[TARGET]`/`[ACTIEID]`/`[GEWEIGERD]`
# marker line out of a script's stdout, and `perform()` uses it internally
# for every OTHER writing tool - `onderhoud_upgrade_fase` bypasses
# `perform()` itself (its runner's argument shape has nothing in common
# with the demo write script's) but the marker CONVENTION is the same one
# scripts/README.md documents for the faserunner too.
from nsmcp.handelen import (
    LIVE_MEASURE_SCRIPT,
    LIVE_MEASURE_TIMEOUT_S,
    RUNNER_NIET_BEOORDEELD,
    WRITE_TOOLS,
    ActionError,
    Allowlist,
    FirmwareBundleError,
    MaintenanceConfig,
    PowerShellNotFound,
    ProcessNotStarted,
    Refusal as ActionRefusal,
    RunnerLogUnopenable,
    RunnerProcessNotStarted,
    RunnerWorkdirUnusable,
    ScriptPinRefused,
    _argument_value,
    _marker,
    _posh_ssh_wire_fingerprint,
    build_live_measure_arguments,
    build_upgrade_arguments,
    echoed_value,
    firmware_target_build,
    perform,
    perform_save,
    run_upgrade_preview,
    script_command,
    sibling_script,
    start_detached,
    typed_runner,
    upgrade_command,
    validate,
    validate_phase_arguments,
)
from nsmcp.headers import headers_answer
from nsmcp.health import health_answer
from nsmcp.hidden_rules import hidden_rules_answer
from nsmcp.impact import what_breaks
from nsmcp.knowledge import KnowledgePin, load_knowledge
from nsmcp.mgmt_plane import mgmt_plane
from nsmcp.names import entity_names
from nsmcp.overzicht import overview
from nsmcp.permissions import allow_all
from nsmcp.powershell import (
    ChildWorkingDirectoryUnusable,
    PowerShellMissing,
    ScriptPinMismatch,
    ScriptPolicy,
    set_script_policy,
)
from nsmcp.preflight import (
    FREE_SPACE_FIELD,
    FREE_SPACE_RESOURCE,
    FREE_SPACE_ROUTE_COLLECTOR,
    FREE_SPACE_ROUTE_SSH,
    free_space_from_script,
    preflight_answer,
)
from nsmcp.retention import Retention
from nsmcp.scorecard import scorecard_answer
from nsmcp.target import load_targets
from nsmcp.tls_baseline import tls_baseline
from nsmcp.update_advice import CurrentBuild, Floor, export_current_build, export_floor, update_advice
from nsmcp.upgrade import (
    START_WAIT_S,
    UndecidedStart,
    UndecidedStarts,
    _bounded_run_echo,
    append_line,
    blocking_phase,
    expired_phases,
    is_safe_run_name,
    latest_run_name,
    ledger_path_for,
    open_phases,
    order_gate,
    phase_has_closing_row,
    read_ledger,
    register_line,
    run_binding_refusal,
    run_id,
    soak_gate,
    stand_answer,
    started_rows,
    wait_for_start,
)

# Reused rather than re-implemented (the same discipline `nsmcp.upgrade_gate`
# itself follows when it imports `nsmcp.upgrade._read_moment` instead of
# keeping its own copy): `_rows_for_target` is the ONE place that scans a
# ledger DIRECTORY for a target's rows across every run file, normalizing
# the target name the same way `upgrade_gate.main()` does - the open-run
# check and the soak check below need exactly that, not one run's own file.
from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target
from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS, proposal_floor_findings, upgrade_plan

# How long a second execution may WAIT for the single-writer gate before it
# is refused. Bounded by the lifetime of the confirmation code itself: a code
# that would have expired before its turn came is not worth waiting for, and
# an unbounded wait is a way to park calls in a server. Module-level so a
# test can shorten it; never a configuration knob, because it follows from
# the TTL rather than from a preference.
WRITER_GATE_WAIT_S = TTL_S

# What a caller reads when that wait ran out. Product copy.
WRITER_BUSY = "een andere handeling loopt nog; probeer straks opnieuw"

# design 3.7: the advice half of the freshness sentence, written out once
# so the singular and the plural cannot drift apart.
FRESHNESS_ADVICE = "ververs voor een betrouwbare leescontrole"

# `onderhoud_upgrade_stand`'s new product
# copy (`_stand_target()`'s refusal and its `doel`/`run`
# behaviour) was asserted only by substring in tests/test_upgrade_stand.py.
# Named here, the same discipline `WRITER_BUSY`/`FRESHNESS_ADVICE` above
# already get, so tests/test_product_surface.py can pin every one
# byte-for-byte.
ONBEKEND_DOEL_TEXT = "onbekend doel; dit doel staat niet in de geconfigureerde doelen"
# `doel` on the export-backed reading tools: this server holds ONE export, so
# a given `doel` must be the target that export describes. The two refusals
# when it is not, or when the export does not say which target it describes.
# Pinned in tests/test_product_surface.py.
EXPORT_ANDER_DOEL_TEXT = "de export van deze server beschrijft een ander doel; ververs eerst met status_ververs"
EXPORT_DOEL_ONBEKEND_TEXT = (
    "de export van deze server zegt niet welk doel hij beschrijft; ververs eerst met status_ververs"
)
# The third refusal: the export NAMES the target and its hash matches, but
# this server holds no record of having collected it for that target - the
# name and the hash both came with the export.
HERKOMST_NIET_VASTGESTELD_TEXT = (
    "doel niet vastgesteld: de export is niet door deze server voor dit doel verzameld;"
    " ververs eerst met status_ververs"
)
# The provenance part of the data age line when no record carries the export.
HERKOMST_AANGELEVERD_TEXT = "niet vastgesteld (aangeleverde export)"
# The evidence of the "gebruik buiten de binding niet vastgesteld" line in the
# proposal of certificaat_vervangen, when the export is not about this action's
# target, or no longer about its current binding.
VERVANGEN_DOEL_EVIDENCE = "scan-doel.txt van de export tegenover het doel van deze handeling"
VERVANGEN_VERSHEID_EVIDENCE = "de export tegenover de handelingen van deze server sinds de laatste scan"
# `onderhoud_upgrade_fase` reads the export again AFTER the code is redeemed;
# when it then describes another target (or none), nothing starts and the code
# is spent. `{reden}` is one of the two refusals above. Pinned in
# tests/test_product_surface.py.
EXPORTDOEL_NA_INWISSELEN_TEXT = "De handeling is niet gestart: {reden}. De bevestigingscode is verbruikt."
# The same refusal on the execution call BEFORE the code is redeemed: the code
# is untouched and can be used again once the export describes this target.
EXPORTDOEL_VOOR_INWISSELEN_TEXT = (
    "De handeling is niet uitgevoerd: {reden}. De bevestigingscode is niet ingewisseld en blijft geldig"
    " tot hij verloopt."
)
EXPORTDOEL_NA_INWISSELEN_EVIDENCE = (
    "scan-doel.txt van de export tegenover het doel van deze handeling, na het inwisselen"
)
# The runner itself could not be started after the redeem: the same honest
# sentence, with a reason that names the KIND of failure only - the
# exception text carries local paths (the runner, its log file) that an
# answer never repeats.
#
# 1.1: the kind is mapped on the TYPE of the error (`_not_started_sentence`),
# five fixed sentences. MEASURED before: every failure of the detached start
# said "het proces of zijn logbestand kon niet worden geopend" (also for an
# unusable working directory), and a script that did not match its pin said
# "Windows PowerShell niet gevonden". `RUNNER_NIET_GESTART_PROCES` keeps its
# name with a narrower meaning: `Popen` itself failed.
RUNNER_NIET_GESTART_REDEN = "de faserunner kon niet gestart worden ({soort})"
RUNNER_NIET_GESTART_WERKMAP = "de vaste werkmap voor kindprocessen is niet bruikbaar"
RUNNER_NIET_GESTART_LOGBESTAND = "het logbestand naast het ledger kon niet worden geopend"
RUNNER_NIET_GESTART_PROCES = "het proces kon niet worden gestart"
RUNNER_NIET_GESTART_SCRIPTPIN = "een script van de faserunner wijkt af van zijn pin"
RUNNER_NIET_GESTART_POWERSHELL = "Windows PowerShell niet gevonden"
# An `ActionError` of no known type: the general sentence, without the text
# of the error, and the target is NOT released - whether a child exists is
# not established.
RUNNER_NIET_GESTART_ALGEMEEN = "de faserunner kon niet gestart worden"
RUNNER_NIET_GESTART_EVIDENCE = "het starten van de faserunner, na het inwisselen van de code"
# The same typed mapping on the routes next to the faserunner that start a
# script of their own (`config_opslaan`; the live measurement says it in its
# read gap).
SCRIPT_NIET_GESTART_REDEN = "het script van deze handeling kon niet gestart worden ({soort})"
SCRIPT_NIET_GESTART_VOORSTEL_TEXT = (
    "Het voorstel kon niet worden opgesteld: {reden}. Er is geen bevestigingscode uitgegeven en er is niets gewijzigd."
)
SCRIPT_NIET_GESTART_EVIDENCE = "het starten van het script van deze handeling"


def _not_started_sentence(exc: BaseException) -> str | None:
    """The fixed sentence for an error that PROVES no child process started,
    chosen on its TYPE; None for every other error. Specific before general:
    `ScriptPinMismatch` and `ChildWorkingDirectoryUnusable` are subclasses of
    `PowerShellMissing`, so they come first. Never the text of the error."""
    if isinstance(exc, (ScriptPinMismatch, ScriptPinRefused)):
        return RUNNER_NIET_GESTART_SCRIPTPIN
    if isinstance(exc, (ChildWorkingDirectoryUnusable, RunnerWorkdirUnusable)):
        return RUNNER_NIET_GESTART_WERKMAP
    if isinstance(exc, (PowerShellMissing, PowerShellNotFound)):
        return RUNNER_NIET_GESTART_POWERSHELL
    if isinstance(exc, RunnerLogUnopenable):
        return RUNNER_NIET_GESTART_LOGBESTAND
    if isinstance(exc, RunnerProcessNotStarted):
        return RUNNER_NIET_GESTART_PROCES
    return None


def _not_started_cause(exc: BaseException) -> str:
    """The CLASS name of the underlying error, for the action log - never
    its text."""
    if isinstance(exc, ProcessNotStarted) and exc.oorzaak:
        return exc.oorzaak
    return type(exc).__name__


# The UNDECIDED START: a confirmed phase whose detached runner was launched
# but whose own `fase_gestart` row this server did not see within the wait
# (or whose wait broke off). The server holds the target for every writing
# tool until that row lands or the phase's own time limit passes
# (`upgrade.UndecidedStarts`) - and already while the confirmed call still
# waits for the row. `{hoe}` is one of the three clauses below: the wait
# still runs (until `{tot}`), it ran out, or it broke off (cancelled or
# raised). Pinned in tests/test_product_surface.py.
ONBESLIST_WACHT_TEXT = "de server wacht nog op zijn regel fase_gestart (tot {tot})"
ONBESLIST_GEWACHT_TEXT = "heeft binnen {wacht} s geen regel fase_gestart geschreven"
ONBESLIST_AFGEBROKEN_TEXT = "het wachten op zijn regel fase_gestart brak af"
ONBESLISTE_START_TEXT = (
    "op dit doel is de start van fase {fase} (run {run}) nog onbeslist: de faserunner is losgekoppeld "
    "gestart en {hoe}; het doel blijft geblokkeerd tot die regel verschijnt of de tijdslimiet van fase "
    "{fase} ({limiet} s) verstrijkt, om {deadline}; vraag de stand na met onderhoud_upgrade_stand"
)
ONBESLISTE_START_EVIDENCE = "faserunner gestart om {gestart}, {wat}, deadline {deadline}"
ONBESLIST_WACHT_EVIDENCE = "het wachten op de regel fase_gestart loopt tot {tot}"
ONBESLIST_GEWACHT_EVIDENCE = "geen regel fase_gestart binnen {wacht} s"
ONBESLIST_AFGEBROKEN_EVIDENCE = "het wachten op de regel fase_gestart brak af"
# `onderhoud_upgrade_stand`'s own finding for the same state.
ONBESLISTE_START_STAND_TEXT = (
    "de start van fase {fase} (run {run}) is onbeslist: de faserunner is losgekoppeld gestart en {hoe}; "
    "elke schrijvende tool op dit doel weigert tot die regel verschijnt of de tijdslimiet van fase "
    "{fase} ({limiet} s) verstrijkt, om {deadline}"
)
# The lift, in the answer that is let through once the limit has passed.
ONBESLISTE_START_VERVALLEN_TEXT = (
    "de start van fase {fase} (run {run}) bleef onbeslist tot de tijdslimiet van {limiet} s: er "
    "verscheen geen regel fase_gestart in het ledger; het doel is weer vrij"
)
ONBESLISTE_START_VERVALLEN_EVIDENCE = (
    "faserunner gestart om {gestart}, geen regel fase_gestart tot de tijdslimiet, om {deadline}"
)
# The evidence of the OPEN PHASE refusal (`_open_phase_refusal()`), which now
# leaves through the same seam as the undecided start: an `Answer` with one
# finding, rendered, never a bare string. What the strictly read ledger of
# the target showed. Pinned in tests/test_product_surface.py.
OPEN_FASE_EVIDENCE = "ledger van dit doel: regel fase_gestart voor fase {fase} zonder sluitregel, gestart om {gestart}"
OPEN_FASE_ZONDER_TIJD_EVIDENCE = (
    "ledger van dit doel: regel fase_gestart voor fase {fase} zonder sluitregel en zonder leesbare starttijd"
)
# The sentence the start-timeout answer itself now ends with.
ONBESLIST_TIMEOUT_TEXT = (
    " Het doel blijft geblokkeerd voor elke schrijvende tool, ook voor een nieuw voorstel, tot die regel "
    "verschijnt of de tijdslimiet van fase {fase} ({limiet} s) verstrijkt, om {deadline}."
)


def ander_doel_text(export_doel: str, level) -> str:
    """The refusal for a configured `doel` that is not the export's own
    target. At 'volledig' it names the target the export DOES describe - a
    real name is what that level shows everywhere, and it tells the operator
    which target to refresh away from. Below it the sentence stays without a
    name: the closing stamp of every answer masks that same name there."""
    if level is Disclosure.FULL:
        return f"de export van deze server beschrijft een ander doel ({export_doel}); ververs eerst met status_ververs"
    return EXPORT_ANDER_DOEL_TEXT


# Shared by the `doel`- and `run`-findings below: one written-out phrase for
# "this value came straight from the argument of this call", not two copies
# that could drift apart.
AANROEP_ARGUMENT_TEXT = "argument van deze aanroep"
DOEL_ENIGE_GECONFIGUREERDE_TEXT = "enige geconfigureerde doel"
RUN_LAATSTE_OP_DOEL_TEXT = "laatste run met een leesbare tijd op dit doel"
RUN_NIET_BEPAALD_TEXT = "niet bepaald"
RUN_GEEN_LEESBARE_TIJD_TEXT = "geen ledgerregel met een leesbare tijd en een run-naam op dit doel"

# These three refusal
# sentences existed only as inline literals - asserted, if at all, by
# substring elsewhere (tests/test_handelen_zonder_code.py) - and pinned
# nowhere byte-for-byte. Named here, the same discipline `WRITER_BUSY`/
# `ONBEKEND_DOEL_TEXT` above already get, so tests/test_product_surface.py
# can pin every one exactly.
RUN_NAAM_ONVEILIG_TEXT = (
    "de fase wordt niet gestart: de run-naam voor deze fase is geen veilig pad-segment; dit "
    "product gebruikt geen ongecontroleerde tekst als bestandsnaam"
)
LEDGERPAD_BUITEN_LEDGERMAP_TEXT = (
    "de fase wordt niet gestart: het ledgerpad voor deze run wijst buiten onderhoud.ledgermap"
)
BEVESTIGER_NIET_VASTGELEGD_TEXT = "niet vastgelegd (dit codekanaal kan de bevestiger niet identificeren)"
# config_opslaan: the texts of its own path. Pinned in
# tests/test_product_surface.py.
CONFIG_OPSLAAN_ZONDER_DOEL_TEXT = (
    "dit doel staat niet in doelen; config_opslaan heeft het adres, het credential-target en de gepinde "
    "hostsleutel van het doel nodig en slaat zonder die drie niet op"
)
CONFIG_OPSLAAN_ROL_TEXT = "wordt bij de uitvoering live bepaald; op een secondary wordt niet opgeslagen"
# The route does not check whether a backup exists, so the sentence does not
# say one does.
CONFIG_OPSLAAN_INVERSE_TEXT = (
    "opslaan heeft geen inverse; de vorige opgeslagen configuratie zit alleen in een backup die vooraf met "
    "onderhoud_backup_maken is gemaakt; config_opslaan controleert dat niet"
)
CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE = "show ns config over SSH, direct na save ns config"
R1_DRIFT_KEUZES_TEXT = (
    "R1 meet de stand zelf met show ns config en opent de driftpoort op een van drie manieren: "
    "aantoonbaar niets gewijzigd sinds de laatste opslag, eerst opgeslagen met config_opslaan op de "
    "primary of het standalone-doel, of bewust geaccepteerd met drift_geaccepteerd=true"
)
# A phase that already carries a closing row in
# THIS RUN's own ledger file is refused HERE, before the faserunner is ever
# launched - `upgrade_gate.main()`'s own `ClosedPhaseError` refuses the same
# repeat, but only AFTER the appliance work already ran (module docstring
# there). Static and generic like `RUN_NAAM_ONVEILIG_TEXT`/
# `LEDGERPAD_BUITEN_LEDGERMAP_TEXT` above - the phase name is already read
# back to the operator elsewhere in this same call (the `fase` finding), so
# this sentence need not carry untrusted ledger content itself.
FASE_AL_GESLOTEN_TEXT = (
    "de fase wordt niet opnieuw gestart: deze fase staat al gesloten in het ledger van deze "
    "run; wie deze fase opnieuw wil proberen, start een nieuwe run"
)
# R0 with doelbuild_geaccepteerd=true while the floor or the current build IS
# known but has no runner form (a FIPS train): `build_upgrade_arguments`
# keeps the acceptance back, so R0 would close on a reason that points back
# at the acceptance. Refused before a code exists, with the real reason.
DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT = (
    "de fase wordt niet gestart: doelbuild_geaccepteerd kan de faserunner niet bereiken, want de vloer of "
    "de huidige build heeft niet de vorm <tak>-<build> die de faserunner aanneemt (zoals een FIPS-trein); "
    "R0 sluit daar ook met doelbuild_geaccepteerd=true"
)


def freshness_line(count: int) -> str:
    """The second sentence under a reading answer, with singular and plural
    both correct Dutch.

    What it says is deliberately narrow: a COUNT of what this product itself
    did since the last scan. It does not say the export is otherwise current,
    because this product cannot know that - a change made by an administrator
    at the CLI never passes through here. The data age above it is the first
    sentence and stays the leading one.

    A count of zero has no sentence: raises rather than returning
    "sinds die scan zijn 0 handelingen uitgevoerd" -
    exactly the noise test_the_freshness_line_says_it_only_knows_its_own_actions's
    own docstring rules out. `WriteCounter.sentence()` already guards this on
    its own call path (`if self._count else None`), but this function is the
    PUBLIC one meant for the writing tools to call, and a guard on only one caller is not
    a guarantee - call `WriteCounter.sentence()` instead of this function
    directly whenever the count might be zero.
    """
    if count < 1:
        raise ValueError("freshness_line(0) has no sentence to give - a count of zero means nothing to report")
    if count == 1:
        return f"sinds die scan is 1 handeling uitgevoerd - {FRESHNESS_ADVICE}"
    return f"sinds die scan zijn {count} handelingen uitgevoerd - {FRESHNESS_ADVICE}"


class WriteCounter:
    """Own successful write actions since the last successful scan.

    Process-local and one per server, not a dictionary keyed by target: there
    is exactly ONE export directory per server process (collect.py), so exactly
    one appliance this process answers reading questions about, and a
    successful `status_ververs` replaces that directory with a fresh scan - at
    which point zero is the only honest count, whichever configured target was
    scanned. Keying it by name would force a choice this product cannot honour:
    the write side knows the `[TARGET]` label the write script reports (an
    object path), the reading side knows the target name in `scan-doel.txt`,
    and those are two different things.

    Everything below runs on the server's event loop thread: `_act()` counts
    after awaiting its worker, `status_ververs` resets after awaiting its scan,
    and the reading tools are synchronous. So no lock - and that is a statement
    about where this is called from, not an assumption about the type.
    """

    def __init__(self) -> None:
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def record_write(self) -> None:
        self._count += 1

    def reset(self) -> None:
        """Back to zero. ONLY after a successful refresh (design 3.7): a failed
        scan left the previous data in force, so the sentence is still true."""
        self._count = 0

    def snapshot(self) -> int:
        """The count as it stands right now, kept aside across an operation
        that takes real time - a scan can run for up to 900 s off-thread
        (`status_ververs`) while this event loop keeps answering other
        calls. A write that lands and is recorded WHILE that scan is still
        in flight must not be erased by the reset that follows it: whether
        the fresh export the scan produced happens to already cover that
        write is an ambiguity this product cannot resolve, and resolving it
        by zeroing the counter resolves it in the direction of silence.

        Call this right before the long-running operation starts, and hand
        the result to `resolve_scan()` once that operation succeeds - never
        `reset()` around a scan, only around an instantaneous one."""
        return self._count

    def resolve_scan(self, baseline: int) -> None:
        """A scan that started when the count was `baseline` has now
        succeeded. Its own fresh export presumably accounts for everything
        counted up to `baseline` - but NOT for a write recorded after that
        point, while the scan was already running - so this subtracts
        `baseline` rather than zeroing outright, which is what makes a
        write that landed during the scan window survive it (one operation
        on `WriteCounter` that knows this rule, rather than
        arithmetic repeated at every call site that resets after a scan).

        Floored at zero rather than trusted to stay non-negative: nothing
        today can make `baseline` exceed the current count between the
        snapshot and this call (the count only ever grows, on this same
        single-threaded event loop, until a reset happens), but this method
        does not lean on that as an external guarantee - a negative count
        would have no sentence to render honestly anyway, so it simply
        cannot occur."""
        self._count = max(0, self._count - baseline)

    def sentence(self) -> str | None:
        return freshness_line(self._count) if self._count else None


# Public MCP description of status_ververs - PRODUCT SURFACE, pinned to
# the master baseline 1cdc563 byte for byte (an AI client reads all of it,
# so all of it is contract; tests/test_product_surface.py snapshots it).
# Passed explicitly to the tool decorator below so the internal function
# docstring can evolve without touching what the customer's client sees.
# The text is the raw baseline docstring, including its original
# indentation, which is why the continuation lines carry eight spaces.
STATUS_VERVERS_DESCRIPTION = (
    "Hoofdstuk status. Scan een ingesteld doel opnieuw. Duurt minuten - dit is geen "
    "snelle aanroep. Gebruik dit alleen als de gegevens niet van vandaag zijn.\n"
    "\n"
    "De scan draait als apart proces op een aparte thread, zodat de server tijdens de "
    "scan bereikbaar blijft voor andere aanroepen, voor een ping en voor een annulering.\n"
    "\n"
    "Annuleren wordt gehonoreerd tot de omwisselgrens: daarvoor wordt de scan afgebroken, "
    "het kindproces echt beeindigd en blijven de vorige gegevens gelden. Daarna is de "
    "omwisseling onomkeerbaar en bij die eerste annulering zegt het antwoord dat met "
    "zoveel woorden.\n"
    "\n"
    "Een scan schrijft nooit over de huidige export heen: hij gaat naar een verse map en "
    "wordt pas na controle omgewisseld. Wat er na een mislukte of afgebroken scan geldt, "
    "staat in het antwoord zelf; de gegevensleeftijd in het volgende antwoord laat zien "
    "of er werkelijk iets ververst is."
)


# How many lines of WRITE SCRIPT output may travel into an answer. The
# script prints a NITRO payload per step on its failure path, and its stderr
# can name the management address; relaying all of it would put an
# unbounded, unread block of appliance data in the model's context. The same
# bounded-tail discipline as `_STDERR_TAIL_LINES` in collect.py, applied to
# the writing side - see `_from_script()` in build_server().
_SCRIPT_LINE_CAP = 10

# `_from_script()`'s OWN line, appended when it caps the script's output -
# never printed by the write script itself. MEASURED: `_script_notes()` used to turn EVERY line of
# `_from_script()`'s output into a finding with the CALLER's evidence
# ("letterlijk uit de uitvoer van het schrijfscript"), including this one -
# a false provenance claim on the one layer whose whole discipline is that
# it never composes the script's own claims. The shape is deterministic
# (built with an f-string in `_from_script()`, never with a line break of
# its own), so it is recognised here, once, rather than guessed at.
#
# NOTED, not fixed: the INVERSE false
# provenance is possible in principle - a write script that itself
# literally prints a line matching this exact shape (e.g. it echoes back
# something that happens to read as "... (3 regels ingekort)") would be
# recognised here as THIS product's own truncation note and get
# `_TRUNCATION_NOTE_EVIDENCE` instead of the caller's evidence, the wrong
# way round. The regex pins the content precisely (a fixed prefix, digits,
# a fixed suffix), so the practical impact is negligible - a real script
# would have to coincidentally print this exact Dutch sentence - and
# restructuring `_script_notes()` to tell the two apart is out of scope
# here; this comment is the record of the edge case for whoever revisits
# this function next.
_TRUNCATION_NOTE = re.compile(r"^\.\.\. \(\d+ regels ingekort\)$")
_TRUNCATION_NOTE_EVIDENCE = "eigen inkortingsregel van dit product (_from_script), niet een regel van het schrijfscript"

# `_from_script()`'s OWN suppression line: returned in place of the script's real output below
# 'volledig', for the same reason `_TRUNCATION_NOTE` above gets recognised
# rather than guessed at - the shape is deterministic (one fixed sentence,
# never produced by the write script itself), so `_script_notes()` can tell
# it apart from a genuine script line and give it its own honest evidence
# instead of the caller's claim of literal script provenance.
_SUPPRESSED_SCRIPT_TEXT = "scriptuitvoer onderdrukt bij openheid beperkt"
_SUPPRESSED_SCRIPT_EVIDENCE = (
    "dit product onderdrukt scriptuitvoer bij openheid beperkt, niet een regel van het schrijfscript"
)


class IdentitySwitched(ToolError):
    """A second handshake tried to switch the caller.

    Subclass of ToolError (not a bare Exception): this is an intended,
    readable refusal - not an unexpected error - so mask_error() must pass
    it through unchanged instead of replacing it with the generic message.
    """


class InvalidClientName(ToolError):
    """The given client name is not admissible in the evidence chain.

    Same reason as IdentitySwitched: an intended refusal, hence a
    ToolError subclass instead of a bare Exception.
    """


def mask_error(exc: BaseException) -> BaseException:
    """Pass intended errors through, replace everything else.

    fastmcp's standard masking does NOT cover argument validation: pydantic
    errors travel a separate path outward and carry internal function names
    and line numbers with them. For a product running at a government
    customer that is a leak. Anything that is not a ToolError (or subclass,
    such as IdentitySwitched, InvalidClientName and Refusal from
    permissions.py) is therefore replaced by one fixed message.

    The fixed message deliberately says the details of THIS error are NOT
    kept, and says exactly what the product does log instead. It used to say
    the product keeps no log at all; since the action log (`_action_log`) that
    sentence would be an unverifiable claim of the kind this product forbids
    itself, only the other way round.
    """
    if isinstance(exc, ToolError):
        return exc
    return ToolError(
        "Onverwachte fout bij het beantwoorden van deze vraag. "
        "De details van deze fout zijn niet bewaard: dit product logt alleen "
        "zijn schrijfhandelingen."
    )


_PINNED: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

_DENIED = {
    "system",
    "administrator",
    "nt authority/system",
    "root",
    "localsystem",
}


def forget_identities() -> None:
    """Test-only: clear the pinning."""
    _PINNED.clear()


def clean_client_name(name: str) -> str:
    clean = " ".join(str(name).split())
    if not clean:
        raise InvalidClientName("lege clientnaam")
    if clean.lower() in _DENIED:
        raise InvalidClientName(f"geleende gezagsnaam geweigerd: {clean!r}")
    if clean.startswith(".") or re.search(r"[/\\:]", clean):
        raise InvalidClientName(f"pad- of URL-vorm geweigerd: {clean!r}")
    return clean


def pin_identity(session, client_name: str) -> str:
    clean = clean_client_name(client_name)
    previous = _PINNED.get(session)
    if previous is None:
        _PINNED[session] = clean
        return clean
    if previous != clean:
        raise IdentitySwitched(f"sessie begon als {previous!r} en meldt zich nu als {clean!r}")
    return clean


def _secure_identity(ctx: Context) -> str:
    """Pins the first identity seen per session - the only hook fastmcp
    1.30.0 offers for that: the Context injected into every tool call,
    which exposes the same ServerSession the initialize handshake filled.
    See the module docstring for why no hook on initialize itself exists.

    Fail-closed: if the identity cannot be read (no session, no handshake
    data, a broken attribute chain), that counts as an empty client name -
    the same refusal clean_client_name() already knows for an empty name,
    not a separate bare error.

    Returns the established client name, so the permissions decision uses
    the same name as the pinning - and does not have to walk the same
    attribute chain a second time.
    """
    try:
        session = ctx.session
        params = getattr(session, "client_params", None)
        info = getattr(params, "clientInfo", None) if params is not None else None
        name = str(getattr(info, "name", "") or "")
    except Exception:  # noqa: BLE001 - any read failure in this chain counts as "no identity"
        session = None
        name = ""
    if session is None:
        raise InvalidClientName("lege clientnaam")
    return pin_identity(session, name)


def _mask_argument_validation(server: FastMCP) -> None:
    """Second hook point: also mask errors from fastmcp's OWN argument
    validation.

    FuncMetadata.call_fn_with_arg_validation validates the incoming
    arguments against the pydantic model BEFORE the tool function - and
    thus our own _guarded() - runs at all. mcp==1.30.0 has no
    mask_error_details flag and no middleware hook on tools/call (only the
    standalone fastmcp package has those, not the SDK-embedded variant
    pinned here; see the module docstring), so this is the most direct
    hook point to enforce the same discipline here too, without patching
    the pinned SDK itself.

    INSTANCE-BOUND, not class-wide: this function wraps, AFTER
    registration, only the fn_metadata instances of the tools of THIS
    server (so call it only after all @server.tool() registrations are
    done). A class-wide patch would mask the argument-validation errors of
    every other FastMCP server in the same process as well - measured and
    repaired in review, see the regression coverage below and
    test_other_unrelated_fastmcp_server_stays_unmasked in
    tests/test_mcp_server.py. FuncMetadata is a pydantic BaseModel: a
    plain assignment (tool.fn_metadata.call_fn_with_arg_validation = ...)
    fails with "... object has no field ...", so the wrap goes through
    object.__setattr__(), which bypasses pydantic's own __setattr__. That
    covers both call paths - the full protocol path and the direct
    server._tool_manager.get_tool(name).run(...) - and leaves FuncMetadata
    as a class, and thus every other server, untouched.

    No idempotency flag needed: every build_server() call creates fresh
    FastMCP and thus fresh FuncMetadata instances (Tool.from_function calls
    func_metadata() again), so double patching of the same instance cannot
    occur here.

    Verified for async tools: `masked()` below is itself an `async def`
    that awaits `original(...)`, and `original`
    (`FuncMetadata.call_fn_with_arg_validation`, unchanged) itself awaits
    `fn(**args)` when `fn_is_async` is true - so the coroutine of an async
    tool is already awaited correctly here, including an
    `await asyncio.to_thread(...)` inside. See
    tests/test_mcp_server.py::test_status_ververs_is_a_coroutine_function
    for the proof.
    """

    def _wrap(original, *, known_names: frozenset[str]):
        async def masked(fn, fn_is_async, arguments_to_validate, arguments_to_pass_directly):
            try:
                return await original(fn, fn_is_async, arguments_to_validate, arguments_to_pass_directly)
            except Exception as exc:  # noqa: BLE001 - same trade-off as _guarded(): mask_error decides
                # FastMCP's ArgModelBase carries no
                # `extra="forbid"` (`ConfigDict(arbitrary_types_allowed=True)`),
                # so an unknown key ALONGSIDE an otherwise complete argument
                # set passes validation silently (pydantic drops it) and `fn`
                # runs anyway. When `fn` THEN raises its own INTENDED
                # `ToolError` (an empty certnaam, an open phase, a soak
                # window, ...), that exception reaches this except clause
                # too - with the same unknown key still sitting in
                # `arguments_to_validate` - and used to have the hint below
                # REPLACE that real refusal. The hint belongs ONLY to a
                # genuine argument-validation failure (`fn` never ran at
                # all); an exception `fn` itself decided is passed straight
                # through unchanged, exactly like `mask_error()` already
                # does for every ToolError elsewhere.
                if isinstance(exc, ToolError):
                    raise
                # Measured: a wrong PARAMETER NAME (`doel=` where
                # this tool's inputSchema names it `doelnaam`) used to fall
                # straight into the fully generic "Onverwachte fout" below -
                # the operator had no way to learn which name this tool
                # actually accepts. Detected from OUR OWN raw
                # `arguments_to_validate` (never from the exception's own
                # `errors()`, which echoes the caller's key and value right
                # back in `input`/`loc`): a key here that is not one of this
                # tool's own known names is exactly that gap. The message
                # names only THIS TOOL'S OWN inputSchema field names, never
                # the aangeleverde naam or waarde - the one rule
                # `_mask_argument_validation` exists to keep.
                onbekend = set(arguments_to_validate) - known_names
                if onbekend:
                    raise ToolError("onbekend argument; deze tool kent: " + ", ".join(sorted(known_names))) from None
                raise mask_error(exc) from None

        return masked

    for tool in server._tool_manager.list_tools():
        original = tool.fn_metadata.call_fn_with_arg_validation
        known_names = frozenset(tool.parameters.get("properties", {}))
        object.__setattr__(
            tool.fn_metadata,
            "call_fn_with_arg_validation",
            _wrap(original, known_names=known_names),
        )


def _write_action_register(
    onderhoud,
    *,
    tool,
    doel,
    actieid,
    uitkomst,
    bevestiger,
    objectnaam,
    doel_vastgesteld=True,
):
    """Appends one `register_line()` row to `onderhoud.actieregister` after an
    EXECUTED write action (design 3.5: R0's "backupobject aanwezig" gate and
    the `terugrolpunt_vast` row read this register and nothing else).

    Returns `None` when there was nothing to say - no register configured, or
    the row was written - and a `Finding` when the register IS configured but
    could not be written. The action itself already happened on the
    appliance, so that is a warning in the answer, never a failure of the
    action, and never silence: a later R0 reads this register, and an
    operator who was told the backup exists must also be told the register
    does not know it."""
    pad = getattr(onderhoud, "actieregister", None) if onderhoud is not None else None
    if pad is None:
        return None
    if uitkomst == "geslaagd" and not doel_vastgesteld:
        return Finding(
            subject="actieregister",
            outcome="geen geslaagde registerregel geschreven",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="het schrijfscript meldde verschillende doelen voor en na de uitvoering",
            reason=(
                "de handeling is uitgevoerd, maar de doelbinding is niet vastgesteld; "
                "controleer het daadwerkelijke doel voordat je vervolgacties uitvoert"
            ),
            subject_is_name=False,
        )
    row = register_line(
        tool=tool,
        doel=doel,
        actieid=actieid,
        uitkomst=uitkomst,
        bevestiger=bevestiger,
        objectnaam=objectnaam,
    )
    try:
        Path(pad).parent.mkdir(parents=True, exist_ok=True)
        append_line(Path(pad), row)
    except OSError as exc:
        return Finding(
            subject="actieregister",
            outcome=f"duurzame registratie NIET vastgesteld ({type(exc).__name__})",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="de registerschrijver meldde een I/O-fout",
            reason=(
                "dit verandert de gemelde handelingsuitkomst niet; controleer het "
                "actieregister voor vervolgacties. De regel kan geheel, gedeeltelijk "
                "of niet zijn opgeslagen"
            ),
            subject_is_name=False,
        )
    return None


_FASTMCP_LOG_LEVEL = "DEBUG" if os.environ.get("NSMCP_DEBUG") else "WARNING"
ACTION_LOG_PREFIX = "[nsmcp-actie]"

ACTION_LOG_VALUE_CAP = 200

_MASK_MIN_LENGTH = 4

DEFAULT_CHAPTERS: frozenset[str] = frozenset(
    {"status", "certificaat", "dienst", "kennis", "beveiliging", "rapport", "ha", "onderhoud", "config"}
)

# The public description of `config_drift`, pinned byte for byte in
# tests/test_product_surface.py.
CONFIG_DRIFT_DESCRIPTION = (
    "Hoofdstuk config. Welke regels alleen in de draaiende configuratie staan en welke alleen in de "
    "opgeslagen configuratie, uit de export. Kopregels en de afsluitende 'Done' tellen niet mee. De "
    "regels zelf staan er alleen bij openheid volledig, en een regel met een herkend geheim of een "
    "geredigeerde waarde nooit. Gebruik dit voordat je configuratie opslaat of een onderhoudsvenster "
    "plant."
)

# The public description of `status_doelen`, pinned byte for byte in
# tests/test_product_surface.py.
STATUS_DOELEN_DESCRIPTION = (
    "Hoofdstuk status. Welke NetScalers deze server kent: per doel de naam, het adres, hoe oud de export "
    "van dat doel is, de laatste onderhoudsrun en welke schrijvende gereedschappen voor dat doel zijn "
    "toegestaan. Credential-namen staan er nooit in. Gebruik dit als eerste vraag als niet duidelijk is "
    "welke doelen er zijn."
)


def _scrub_ssh_text(text: str, target) -> str:
    """`collect._scrub_error_text()` for a text out of one of the small SSH
    scripts: the target's known values (address, credential target, TLS
    fingerprint) plus its pinned SSH host key, in the stored AND in the
    Posh-SSH wire form - a host-key refusal names the key it expected."""
    scrubbed = _scrub_error_text(str(text), target)
    stored = str(target.ssh_hostsleutel_vingerafdruk or "")
    try:
        wire = _posh_ssh_wire_fingerprint(stored)
    except ValueError:
        wire = ""
    for value in sorted({v for v in (stored, wire) if v}, key=len, reverse=True):
        scrubbed = re.sub(re.escape(value), "<hostsleutel>", scrubbed, flags=re.IGNORECASE)
    return scrubbed


def _context_values_to_mask(target_label: str | None) -> tuple[str, ...]:
    """The values of ONE action context that bulk write-script output must
    not repeat: the [TARGET] label the script reported, plus the identifying
    components of that label.

    The label has the shape "servicegroup/<groep>/<lid>:<poort>". Two kinds
    of component are deliberately kept OUT of the result: the label's first
    "/"-segment, which is the structural object type, and any purely numeric
    component, which is a port. Neither identifies anything on its own, while
    masking them turns the one sentence the operator confirms on into
    "<doel> '<doel>': lid '<doel>:<doel>'" - all of the readability gone, not
    one leak prevented.

    The same minimum length applies to the label itself as to its components:
    the write script decides what it prints after [TARGET], and a short label
    matched unanchored rewrites longer names ("web" turns "gjkdemo_web01"
    into "gjkdemo_<doel>01", which reads as a real object name).
    """
    label = str(target_label or "").strip()
    if len(label) < _MASK_MIN_LENGTH:
        return ()
    segments = label.split("/")
    # Only a structured label HAS an object-type segment to drop; an
    # unstructured one is all identifier.
    identifying = segments[1:] if len(segments) > 1 else segments
    components = [part for chunk in identifying for part in chunk.split(":")]
    return (
        label,
        *[p for p in components if len(p) >= _MASK_MIN_LENGTH and not p.isdigit()],
    )


def _action_log(
    *,
    tool: str,
    arguments: dict,
    target: str | None,
    action_id: str | None,
    outcome: str,
    client: str,
    marker: str | None = None,
    bevestiger: str | None = None,
    oorzaak: str | None = None,
) -> None:
    """ONE structured line per write action, on stderr.

    Diagnostics and accountability, never truth: the appliance and
    the ledger of a runner phase are the truth. What may NOT be in here is
    stated as a rule rather than assumed: never the confirmation code, never a
    secret, and never an argument value longer than ACTION_LOG_VALUE_CAP
    characters.

    `client` is what the caller said it was during the handshake. There is no
    authentication, so the line says so in a field of its own instead of
    letting a reader assume the name was verified.

    `bevestiger` is the code-bound identity returned at redemption by an
    identifying channel. A proposal or a channel without identity records null.

    `doel` and `actieid` are null when the write script reported neither -
    never the string "None", which reads as a target name in a line that is
    meant to be read (the same trap `_report_orphan` avoids in its sentence).

    `uitkomst` also distinguishes "voorstel" and "gestart". Besides "geslaagd" and "mislukt"
    there is "onbekend": the run started, the code was already redeemed, and
    then the caller cancelled or the script threw. The appliance may well have
    changed and nothing read it back, so the line exists and says exactly
    that - a silent branch there would be the one place where accountability
    matters most.

    Module level, not a closure in `build_server()`: it needs nothing from
    that scope, and only from here can the value cap be measured at all -
    through a tool no argument can ever be long enough (see the constant).
    """
    row = {
        "tijd": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client": client,
        "client_zelfverklaard": True,
        "tool": tool,
        "argumenten": {
            name: (str(value) if len(str(value)) <= ACTION_LOG_VALUE_CAP else str(value)[:ACTION_LOG_VALUE_CAP] + "...")
            for name, value in arguments.items()
        },
        "doel": target or None,
        "actieid": action_id or None,
        "bevestiger": bevestiger,
        "voorstel": marker,
        "uitkomst": outcome,
    }
    # 1.1: when a child process did not start, the CLASS of the underlying
    # error (never its text, which carries local paths). Only on those rows.
    if oorzaak is not None:
        row["oorzaak"] = oorzaak
    try:
        print(
            f"{ACTION_LOG_PREFIX} {json.dumps(row, ensure_ascii=True, sort_keys=True)}",
            file=sys.stderr,
            flush=True,
        )
    except Exception:  # noqa: BLE001 - never fatal after a redeem
        # A write to stderr can fail (a broken pipe once the client walked
        # away, a full disk under a redirected stderr). This log is
        # accountability, never a gate: letting that OSError out would reach
        # `_guarded_async`'s except Exception and `mask_error` would report a
        # handling that DID change the appliance as "Onverwachte fout" - the
        # same lie the branches around the real run are built to avoid. Silent
        # by necessity and not by taste: stderr is the only channel this
        # process has for a message, so there is nowhere left to report to.
        pass


def build_server(
    export_dir: Path,
    knowledge_path: Path,
    *,
    targets_path: Path | None = None,
    collect_script: Path | None = None,
    run=None,
    decide=None,
    disclosure: Disclosure = Disclosure.FULL,
    pseudonym_table_path: Path | None = None,
    chapters: frozenset[str] = DEFAULT_CHAPTERS,
    action_script: Path | None = None,
    fixture_dir: Path | None = None,
    action_run=None,
    code_presenter=None,
    retention: Retention | None = None,
    allowlist: Allowlist | None = None,
    onderhoud: MaintenanceConfig | None = None,
    forbidden_addresses: tuple[str, ...] = (),
    live_run=None,
    knowledge_pin: KnowledgePin | None = None,
    provenance_dir: Path | None = None,
    script_policy: ScriptPolicy | None = None,
):
    # 1.0.2: how this server starts PowerShell - the pins of
    # `scriptpin` and the configured execution policy. Set for EVERY server
    # built, so a server without them starts from the documented default.
    set_script_policy(script_policy if script_policy is not None else ScriptPolicy())
    # action_script, fixture_dir en action_run worden hier alleen
    # aangenomen en doorgegeven - de schrijvende tools die ze gebruiken
    # staan verderop geregistreerd (_act), onder een chapters-poort net als hieronder.
    #
    # `code_presenter` is HET kanaal waarlangs de bevestigingscode de beheerder
    # bereikt - en het model NIET. THE seven-parameter contract for that
    # callable is stated in ONE place: the comment above `KINDS` in
    # code_channel.py - not restated here (two
    # independent copies of the same signature had drifted apart, five
    # parameters here versus six there). Faalt met een exception als de code
    # niet getoond kon worden; `start.py` leidt het kanaal af uit
    # `handelen.codekanaal` (venster of bestand, zie code_channel.py). Zonder
    # kanaal worden de schrijvende gereedschappen niet aangemeld: een code
    # die nergens heen kan, maakt de tweede stap onbereikbaar.
    #
    # `allowlist` is WHAT THE ADMINISTRATOR ALLOWS, per target per tool - read
    # from `handelen.toegestaan` by start.py. An empty one is the honest
    # default for a library caller that does not write at all: every writing
    # tool then refuses, which is what "nothing configured" must mean.
    allowlist = allowlist if allowlist is not None else Allowlist(per_target={})
    # `forbidden_addresses`: read from
    # `handelen.verboden_adressen` by start.py, empty by default. Handed to
    # `build_upgrade_arguments()` at both call sites below (`-VerbodenAdressen`)
    # so `Invoke-GjkUpgradeFase.ps1`'s address guard has something real to
    # compare against without that address ever living in this repository.
    #
    # `knowledge_pin`: the package the operator approved (`kennispin`, read
    # by start.py). None - the default, and what a configuration without the
    # field produces - loads the package but leaves every floor and CVE
    # statement on it `[niet vastgesteld]`: whoever can write the knowledge
    # path could otherwise change the knowledge without a trace. A pin the
    # package does not match refuses the package outright.
    #
    # `provenance_dir`: where `status_ververs` records every export it
    # collected (`export.record_provenance`), OUTSIDE the export map - start.py
    # passes the ledger map's `herkomst` or a `herkomst` map under the
    # configuration's directory. None (the default) records nothing and so
    # proves nothing: every target-bound answer and every writing tool that
    # relies on the export then refuses it, and every answer's data age line
    # says the export's provenance is not established.
    #
    # `live_run` starts the small SSH read script of the pre-flight
    # (`Invoke-GjkLiveMeting.ps1`); `None` is `handelen.typed_runner`, the
    # same starter and the same polite stop the write script gets, with a
    # typed start failure (1.1). A test
    # hands in a stub, exactly like `run` for the collector.
    server = FastMCP("netscaler-mcp", log_level=_FASTMCP_LOG_LEVEL)
    # 1.0.2: FastMCP takes no version, and the low-level server then
    # reports the version of the mcp library in `initialize`. The product
    # version goes in its place (`serverInfo.version`).
    server._mcp_server.version = __version__
    targets = load_targets(targets_path) if targets_path else {}
    decision = decide or allow_all
    # The pseudonym table (pseudonym -> real name) stays LOCAL next to the
    # export: it holds real object names and must never reach the model.
    pseudonym_table_path = pseudonym_table_path or (export_dir.parent / "openheid-vertaaltabel.json")
    # One counter for this server process; see WriteCounter for why it is
    # not keyed by target.
    writes_since_scan = WriteCounter()

    def _knowledge():
        # THE one read of the knowledge package, for every tool - so the pin
        # is applied on every route, never on most of them.
        #
        # "Today" must use the SAME time frame as the data age below (UTC):
        # date.today() is the LOCAL day and, just after local midnight while
        # the UTC day had not rolled over yet, produced a knowledge base that
        # called itself a day too old. Two time frames in one answer is
        # exactly the contradiction this product must not have (see the
        # regression coverage below).
        return load_knowledge(knowledge_path, today=datetime.now(UTC).date(), pin=knowledge_pin)

    def _load():
        return load_export(export_dir), _knowledge()

    def _herkomst(export) -> str | None:
        """The provenance part of the data age line: this server's own
        record of collecting exactly this export (in any of its scans of the
        target the export names), or that there is none. Only for this
        server's export map; None when there is no manifest to speak of."""
        if export.manifest_hash is None or Path(export.directory) != Path(export_dir):
            return None
        target = None if export.target_name_refused else export.target_name
        moment = collected_at_some_point(provenance_dir, target, export.manifest_hash, export_dir)
        if moment is None:
            return HERKOMST_AANGELEVERD_TEXT
        return f"verzameld door deze server op {moment.astimezone(UTC).strftime('%Y-%m-%d %H:%M')} UTC"

    def _stamp(answer: Answer, export, today=None) -> Answer:
        """`stamp_data` for an answer built from `export`: its age, the
        target it names and where it came from, in ONE place - so no
        export-backed answer leaves without its provenance."""
        return stamp_data(
            answer,
            export.collected_at,
            today if today is not None else datetime.now(UTC).date(),
            export.target_name,
            provenance=_herkomst(export),
        )

    def _record_provenance(name: str, export, collected_hash: str | None) -> str:
        """After a successful scan of `name`: the record that says this
        server collected THIS export for `name`. Returns "" when it was
        written, else the sentence the scan answer adds - a scan whose
        provenance was not recorded leaves an export every target-bound
        answer refuses, and the operator must hear that now.

        `collected_hash` is the manifest hash `collect()` itself computed in
        its work map (`SwapGate.manifest_hash`). The record carries that
        hash, and only when the export map still holds that very manifest:
        whoever can write the export map could otherwise replace the export
        between the swap and this reading and have it recorded as
        collected."""
        gevolg = "een antwoord met doel en elke schrijvende tool weigeren deze export tot een volgende scan"
        if provenance_dir is None:
            return f"De herkomst is niet vastgelegd: deze server heeft geen herkomstmap; {gevolg}."
        if collected_hash is None or export.manifest_hash != collected_hash:
            return (
                "De herkomst is niet vastgelegd: de export in de exportmap is niet de export die deze scan"
                f" verzamelde; {gevolg}."
            )
        if export.target_name != name or export.target_name_refused or export.manifest_hash is None:
            return (
                "De herkomst is niet vastgelegd: de export in de exportmap beschrijft niet het gescande doel;"
                f" {gevolg}."
            )
        try:
            record_provenance(provenance_dir, name, collected_hash, export_dir, datetime.now(UTC))
        except OSError as exc:
            return f"De herkomst is niet vastgelegd ({type(exc).__name__}); {gevolg}."
        return ""

    def _with_explanation(text: str, knowledge, tool: str) -> str:
        """THE closing composition of a reading answer, and the one place every
        reading tool ends up. Two things get added here, in this order.

        First, per design 3.7: the freshness sentence, directly under the data
        age, whenever this server has performed a write action since the last
        successful scan. Added to the RENDERED text and not built into the
        Answer, so every disclosure level keeps it - there is no name in it, so
        there is nothing for the seam to mask.

        Then the knowledge package's own explanation of this TOOL (not of an
        arbitrary term - that is kennis_uitleg's job), when the package carries
        one for it (`knowledge.explanations[tool]`, JSON key "uitleg").
        Read-only and additive: a package without an entry for this tool leaves
        the answer exactly as `render()`/`stamp_data()` built it.

        `kennis_uitleg` deliberately does not pass through here: it reads no
        export, so it has no data age, and a sentence about "die scan" would
        point at a scan its answer never mentioned.
        """
        freshness = writes_since_scan.sentence()
        if freshness is not None:
            text = f"{text}\n{freshness}"
        explanation = safe_text(knowledge.explanations.get(tool, "").strip())
        return f"{text}\n\nUitleg: {explanation}" if explanation else text

    def _decide(ctx: Context, tool: str, arguments: dict) -> str:
        """The permissions decision itself: pin the identity (or refuse
        fail-closed), then call `decision()`. THE one place that does so -
        for both the synchronous front door (`_guarded`, three answering
        tools) and the asynchronous one (`_guarded_async`,
        status_ververs). Without this function each front door would
        maintain its own copy of "read identity, then judge" - and this
        codebase has been bitten before by two readers of the same
        attribute chain drifting apart (see `_secure_identity` above).
        With one `_decide()` the two front doors cannot diverge here: a
        change to the decision logic (say, a real permissions system
        later) needs only one place.

        `arguments` receives the NORMALIZED value: every caller below
        normalizes ONCE, before `_decide()`/`_guarded()`/`_guarded_async()`
        are called, and passes that same canonical value to both
        `arguments` here and to `work()` - see `_normalize()` further down
        and the module docstring of permissions.py. (Passing the raw value
        was a proven policy bypass.)

        Returns the established client name, so a caller that has to NAME the
        caller afterwards (the action log in `_act`) uses the same name the
        decision judged instead of walking the identity chain a second time -
        the drift this file has been bitten by before.
        """
        client = _secure_identity(ctx)
        decision(client, tool, arguments)
        return client

    def _mask_if_needed(exc: Exception) -> None:
        """THE one place that replaces an unexpected error with the fixed
        message (`mask_error()`) and lets an intended `ToolError` pass
        unchanged.

        Shared by `_guarded()` and `_guarded_async()` deliberately: the two
        used to carry a literal copy of this line each, and two copies that
        are identical today can drift apart tomorrow (see the
        regression coverage below).
        """
        raise mask_error(exc) from None

    def _guarded(ctx: Context, work, tool: str, arguments: dict):
        """Every SYNCHRONOUS tool runs through this: first the shared
        decision point (`_decide`, see there), then the work, with the same
        error masking as `_guarded_async` below (shared via
        `_mask_if_needed()`, see there).

        Deliberately no separate `except Refusal` branch: Refusal is a
        ToolError subclass (permissions.py), so a refusal follows the
        generic `except Exception -> _mask_if_needed()` handling below and
        comes out of it - just like IdentitySwitched and InvalidClientName -
        UNCHANGED: RAISED with its own text, not returned as result text.
        A Refusal from `work()` follows exactly the same route as any
        ToolError from `work()` always did (for example the empty-certnaam
        error from `_require_nonempty`): raised unmasked by the same single
        `except Exception` branch.
        """
        try:
            _decide(ctx, tool, arguments)
            return work()
        except Exception as exc:
            # Deliberately Exception, not BaseException: KeyboardInterrupt,
            # SystemExit and asyncio.CancelledError (which inherits from
            # BaseException, not Exception, precisely so broad handlers like
            # this one do not swallow it) must reach the caller or the event
            # loop - that is not an "error answering this question" that
            # should be masked.
            _mask_if_needed(exc)

    async def _guarded_async(ctx: Context, work, tool: str, arguments: dict, *, client_slot: list | None = None):
        """ASYNCHRONOUS counterpart of `_guarded`, for the only tool that
        needs it: `status_ververs` (see the module docstring). `work` is
        an async callable here (a coroutine function without arguments)
        instead of a plain callable, so the blocking scan inside can run
        via `asyncio.to_thread(...)` without occupying the server's event
        loop.

        Shares `_decide()` with `_guarded()` above - same identity and
        permissions logic, no second copy that can drift. Also shares
        `_mask_if_needed()` - same reason, see there. What remains is
        exactly what Python's syntax requires: `work()` is awaited here
        instead of called bare, because that is the only way to wait on a
        coroutine from inside a coroutine. The same reason as in
        `_guarded()` applies to the `except Exception` breadth:
        CancelledError inherits from BaseException, not Exception, so a
        cancellation (the whole point of the async tool) never runs into
        the masking here - see also `status_ververs` below, which catches
        CancelledError itself (to set the stop signal) before re-raising
        it, so it never reaches this `except Exception` anyway.

        `client_slot`, when given, receives the client name `_decide()` just
        established - filled BEFORE `work()` runs, so `work()` can name the
        caller in a log line without reading the identity chain itself. Only
        `_act()` passes one; the reading tools log nothing."""
        try:
            client = _decide(ctx, tool, arguments)
            if client_slot is not None:
                client_slot.append(client)
            return await work()
        except Exception as exc:
            _mask_if_needed(exc)

    def _normalize(value) -> str:
        """Normalizes ONCE - before the permissions decision, so decision
        and tool see the same canonical value. See the module docstring of
        permissions.py: normalizing AFTER the decision (or, equivalently,
        only inside `work()`) lets the decision judge a different form of
        the value than the tool ends up using - bypassable with, say, a
        leading space."""
        return str(value).strip()

    def _require_nonempty(value: str, message: str) -> str:
        if not value:
            raise ToolError(message)
        return value

    def _resolve_doel(gegeven: str, bekend) -> str | None:
        """The configured target a caller names, or None. ONE resolver for
        every tool that takes a `doel`: the export-backed reading tools
        (`_load_for`), the ledger-reading tools (`_stand_target`) and the
        writing path (`_target_for`), each against its own set of names.

        A real name is itself. At 'beperkt' a caller only ever SAW
        pseudonyms (`status_doelen` masks every target name), so a value with
        the pseudonym shape is looked up in the operator's table
        (`resolve_pseudonym`) and counts only when it maps onto one of
        `bekend`. Anything else is None, and every caller refuses None with
        one sentence: an unknown name, an unissued pseudonym and a pseudonym
        of something that is not a target cannot be told apart, so the
        resolver is no oracle for what the table holds. At 'volledig' and
        'minimaal' this server shows no pseudonym, so it resolves none.
        """
        if gegeven in bekend:
            return gegeven
        if disclosure is not Disclosure.LIMITED or not has_pseudonym_shape(gegeven):
            return None
        echt = resolve_pseudonym(gegeven, tuple(sorted(bekend)), pseudonym_table_path)
        return echt if echt is not None and echt in bekend else None

    def _via_pseudoniem(gegeven: str, gekozen: str) -> tuple[str, ...]:
        """The real target name, for the masking set of an answer, when the
        caller reached that target through a pseudonym: that caller never saw
        the name, and the answer must not be where it learns it. A target the
        caller named itself, or none, changes nothing here."""
        gegeven = gegeven.strip()
        return (gekozen,) if gekozen and gegeven and gegeven != gekozen else ()

    def _gekozen_doel(doel: str) -> str:
        """The configured target a reading tool's `doel` names, or "" when
        the caller left it out (the behavior without `doel`, unchanged). An
        unknown one is refused without repeating it."""
        if not doel:
            return ""
        gekozen = _resolve_doel(doel, targets)
        if gekozen is None:
            raise ToolError(ONBEKEND_DOEL_TEXT)
        return gekozen

    def _export_is_van(gekozen: str, export) -> None:
        """A chosen target must be the target this export describes: there is
        ONE export per server (`status_ververs` writes every target into the
        same directory), so an answer for any other target would describe
        the wrong appliance. An export that does not record its target (or
        records one without the shape of a name) cannot prove it is the
        chosen one - refused as well, never assumed."""
        if not gekozen:
            return
        if export.target_name is None or export.target_name_refused:
            raise ToolError(EXPORT_DOEL_ONBEKEND_TEXT)
        if export.target_name != gekozen:
            raise ToolError(ander_doel_text(export.target_name, disclosure))
        # The name and the hash in `scan-doel.txt` travel WITH the export;
        # only this server's own record, outside the export map, says it
        # collected this manifest for this target - and it must be the
        # newest scan of that target, not an older one put back.
        if collected_for(provenance_dir, gekozen, export.manifest_hash, export_dir) is None:
            raise ToolError(HERKOMST_NIET_VASTGESTELD_TEXT)

    def _load_for(doel: str):
        """`_load()` for a reading tool with a `doel`: empty is `_load()`
        itself; given, it must name a configured target (`_gekozen_doel`)
        AND the target of the export (`_export_is_van`). Called inside
        `work()`, behind the decision point, like every other refusal."""
        gekozen = _gekozen_doel(doel)
        export, knowledge = _load()
        _export_is_van(gekozen, export)
        return export, knowledge

    def _inside_export_root(name: str) -> Path:
        """A directory name UNDER the export root, never a path.

        `is_safe_run_name()` (upgrade.py) is reused rather than a bespoke
        blacklist of "/", "\\" and "..": that function already is the
        positive allowlist this codebase applies to "safe as ONE filesystem
        path segment" (the same shape gate `export._is_object_name`'s own
        comment argues for - enumerating what is ALLOWED, never what is
        dangerous). It already refuses a path separator, a drive/UNC/ADS
        colon, ".", ".." and a reserved Windows device name; nothing here
        repeats that grammar a second time.

        A SAFE NAME is not enough by itself - a Windows
        junction or symlink named "export" (`mklink /J`) passes
        `is_safe_run_name` and `is_dir()` alike while pointing anywhere on
        disk. `export.plain_path()` is the same containment discipline
        `retention._owned_manifest` already applies to a KEPT sibling
        (refuse a symlink or reparse point anywhere in the path, including
        every ancestor); the `resolve().parent` check afterwards is the
        second half of that same discipline - confirming the resolved
        path still sits directly under THIS export's parent, belt and
        braces rather than either alone.

        The refusal does not repeat the name - repeating it would tell the
        caller whether that path exists.
        """
        if not is_safe_run_name(name):
            raise ToolError(
                "de naam van een exportmap mag geen pad zijn; geef alleen de mapnaam"
                " zoals die naast de huidige export staat"
            )
        candidate = export_dir.parent / name
        not_a_sibling = ToolError(
            "die exportmap staat niet naast de huidige export; vraag rapport_dekking welke gegevens er zijn"
        )
        if not plain_path(candidate, directory=True):
            raise not_a_sibling
        try:
            resolved_parent = candidate.resolve().parent
        except OSError:
            raise not_a_sibling from None
        if resolved_parent != export_dir.parent.resolve():
            raise not_a_sibling
        return candidate

    if "certificaat" in chapters:

        @server.tool()
        def certificaat_wat_verloopt_er(horizon_dagen: int = 90, doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk certificaat. Welke certificaten verlopen binnen de horizon, gesorteerd op impact in plaats van op dagen: eerst wat aan een virtuele server hangt, dan wat andere certificaten uitgeeft, dan de rest. Met sleutellengte, handtekeningalgoritme, bewijs en leesgaten. Gebruik dit als de vraag gaat over wat er binnenkort verloopt."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = what_expires(export, knowledge, horizon_dagen)
                answer = _stamp(answer, export)
                # extra_names comes from the export itself (names_from_export),
                # not just from what the answer happens to carry as subjects -
                # see disclosure.py for the full reasoning.
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="certificaat_wat_verloopt_er",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "certificaat_wat_verloopt_er",
                )

            return _guarded(
                ctx, work, "certificaat_wat_verloopt_er", {"horizon_dagen": horizon_dagen, "doel": doel_clean}
            )

        @server.tool()
        def certificaat_wat_breekt_er(certnaam: str, doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk certificaat. Welke virtuele servers vallen uit als dit certificaat verloopt, ook via de certificaten die het uitgeeft, en waar het verder in gebruik is: SSL-diensten, SAML-acties, SAML-IdP-profielen en SSL-servicegroups. Gebruik dit als de vraag gaat over impact of keten. Kent de export de naam niet, dan noemt het antwoord bij openheid volledig de certificaten die de term bevatten; bij beperkt of minimaal blijft die lijst weg. Stel de vraag dan opnieuw met een volledige naam."""
            name = _normalize(certnaam)
            doel_clean = _normalize(doel)

            def work():
                clean = _require_nonempty(name, "certnaam mag niet leeg zijn")
                export, knowledge = _load_for(doel_clean)
                answer = what_breaks(export, knowledge, clean)
                answer = _stamp(answer, export)
                # See certificaat_wat_verloopt_er above. The certnaam from the
                # argument travels as `caller_name`, SEPARATELY from the
                # structural export names, because its origin decides how the
                # seam may handle it: a name the export knows is masked exactly
                # as before, a caller-invented one may never be treated as a
                # real appliance name. Passing it as a plain extra_name (the
                # old `... + (clean,)`) was a measured defect - see
                # disclosure._collect_names() for what it caused.
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="certificaat_wat_breekt_er",
                        extra_names=names_from_export(export),
                        caller_name=clean,
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "certificaat_wat_breekt_er",
                )

            return _guarded(ctx, work, "certificaat_wat_breekt_er", {"certnaam": name, "doel": doel_clean})

        @server.tool()
        def certificaat_wat_moet_ik_doen(certnaam: str, doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk certificaat. Wijziging, terugrol en terugleescontrole voor dit certificaat - alleen als de impact vaststaat. Gebruik dit als de vraag is wat er nu moet gebeuren. Kent de export de naam niet, dan noemt het antwoord bij openheid volledig de certificaten die de term bevatten; bij beperkt of minimaal blijft die lijst weg. Stel de vraag dan opnieuw met een volledige naam."""
            name = _normalize(certnaam)
            doel_clean = _normalize(doel)

            def work():
                clean = _require_nonempty(name, "certnaam mag niet leeg zijn")
                export, knowledge = _load_for(doel_clean)
                # The allowlist travels along so the steps can say whether
                # this product may execute them (advice.advice_label). With a
                # `doel` the target is that one - `_load_for` has just proven
                # it is the target of this export. Without one it can only be
                # implied: with exactly one configured target it is that one,
                # with more than one it is unknowable and stays None - which
                # advice_label reads fail-closed as "niet in de allowlist".
                #
                # `writing_allowed` is THE flag this server registered the seven
                # writing tools on, read here and not recomputed - a second
                # copy of that condition could drift and then the advice would
                # promise an execution through a tool that is not registered.
                # It is assigned further down in build_server(), before this
                # closure can ever run: the tools only answer after the server
                # is fully built.
                allowlist_targets = allowlist.targets()
                if doel_clean:
                    advice_target = export.target_name
                else:
                    advice_target = allowlist_targets[0] if len(allowlist_targets) == 1 else None
                answer = what_to_do(
                    what_breaks(export, knowledge, clean),
                    knowledge,
                    clean,
                    allowlist=allowlist,
                    target=advice_target,
                    writing_tools_offered=writing_allowed,
                )
                answer = _stamp(answer, export)
                # The happy path of this tool puts the affected vservers in
                # FREE TEXT ("2. Koppel het om op: ..."), and `what_to_do()`
                # returns a bare Answer, not an ImpactAnswer, so
                # affected_vservers does not even exist on THIS answer.
                # extra_names from the export solves that structurally: every
                # vserver name the export knows is in there, regardless of
                # which text field it appears in. The certnaam travels as
                # `caller_name` for the same reason as in
                # certificaat_wat_breekt_er above.
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="certificaat_wat_moet_ik_doen",
                        extra_names=names_from_export(export),
                        caller_name=clean,
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "certificaat_wat_moet_ik_doen",
                )

            return _guarded(ctx, work, "certificaat_wat_moet_ik_doen", {"certnaam": name, "doel": doel_clean})

    if "status" in chapters:
        if targets_path is not None and collect_script is not None:

            @server.tool(description=STATUS_VERVERS_DESCRIPTION)
            async def status_ververs(doelnaam: str, *, ctx: Context) -> str:
                """Re-scan a configured target (the public MCP description is the
                pinned module constant above, not this internal docstring).

                The scan runs on a separate thread; the server stays reachable
                during it. Cancellation is honored up to the commit boundary of
                the swap: before it the scan aborts and the previous data stays
                in force, after it the swap has gone through and the answer says
                so explicitly.
                """
                # This tool's confirmation
                # sentences ("De scan van '<doelnaam>' is gelukt", ...) echo only
                # the CALLER'S OWN `doelnaam` argument - that discloses nothing
                # the caller did not just type, so those stay hand-written. The
                # CLOSING STAMP below is different: it carries `export.target_name`,
                # the twelfth name family `names_from_export()` collects, and it
                # must obey the SAME openheid rule as the other twelve read tools -
                # so it is built through the one seam (`render()`), never a second
                # masking path. The unknown-target branch just below has its own
                # equivalent reasoning: an ENUMERATION of every configured target
                # is not the caller's own input, so it does not get the same pass.
                name = _normalize(doelnaam)

                async def work():
                    if not targets:
                        return (
                            f"{GEEN_DOEL_TEXT}\n"
                            "Een doel toevoegen is een bewuste handeling: adres, credential-target en de "
                            "certificaatafspraak."
                        )
                    if name not in targets:
                        if disclosure is Disclosure.FULL:
                            return f"Onbekend doel '{name}'. Ingesteld zijn: {', '.join(sorted(targets))}."
                        # Same rule as the writing tools' allowlist refusal
                        # (`_act()`/`handelen.validate()` further down in this
                        # file, gated to 'volledig' by the disclosure gate on the
                        # writing tools): an enumeration of every CONFIGURED
                        # target hands the model real names it never asked
                        # about - a de-pseudonymisation oracle for exactly the
                        # value the closing stamp below pseudonymises. Withheld
                        # below 'volledig'; the refusal itself still stands.
                        return f"Onbekend doel '{name}'."
                    # Belt and braces since security 19: the gate above only
                    # registers this tool when a collect script is configured, so
                    # this branch cannot be reached through a registered tool. It
                    # stays because collect() below takes a Path, not a Path|None,
                    # and because a fail-closed answer beats a masked TypeError if
                    # a later change ever widens the gate.
                    if collect_script is None:
                        return (
                            "Er is geen verzamelscript ingesteld, dus deze server kan niet zelf scannen.\n"
                            "De vorige gegevens blijven gelden."
                        )
                    baseline = writes_since_scan.snapshot()
                    stop = SwapGate()
                    try:
                        # asyncio.to_thread: collect() blocks for up to 900 s (the
                        # underlying PowerShell collector script, see collect.py) -
                        # without this offload that blockage would sit on the
                        # thread of the server's own event loop, see the module
                        # docstring. `stop` is the channel through which a
                        # cancellation can really abort the background scan.
                        await asyncio.to_thread(
                            collect,
                            targets[name],
                            export_dir,
                            collect_script,
                            run=run,
                            stop=stop,
                            # The previous export is retained (with a
                            # term) when `bewaren` is configured; without it collect()
                            # keeps its own default, so the call shape stays the release's.
                            **({"retention": retention} if retention is not None else {}),
                        )
                    except asyncio.CancelledError:
                        # Cancellation contract (measured, not merely assumed):
                        # - `stop.request_cancellation()` is a lock-free, atomic
                        #   Event.set() and runs SYNCHRONOUSLY on the event loop.
                        #   It must never wait on an executor: a saturated pool
                        #   would queue the stop request behind the very scan it
                        #   has to stop.
                        # - Only learning the outcome (`stop.learn_outcome()`) can
                        #   block on the commit lock, so only that call is
                        #   offloaded to a thread and wrapped in asyncio.shield():
                        #   a second cancellation then breaks OUR await, not the
                        #   background call - we re-raise honestly instead of
                        #   guessing "committed"/"aborted" without knowing.
                        stop.request_cancellation()
                        try:
                            outcome = await asyncio.shield(asyncio.to_thread(stop.learn_outcome))
                        except asyncio.CancelledError:
                            # Second cancellation, RECEIVED WHILE we were waiting on
                            # the lock: thanks to asyncio.shield() above, the
                            # shielded `stop.learn_outcome()` call keeps running in
                            # the background - `_stop` has long been True anyway
                            # (set synchronously, above), so there is nothing new
                            # for the worker thread to gain. We no longer know the
                            # outcome in time to report it honestly (that would be
                            # guessing), so we pass this second CancelledError on to
                            # the caller - the same "never swallowed" rule as for
                            # the FIRST cancellation, now for the second: no hang,
                            # no fabricated "aborted" or "completed" we did not
                            # verify. If the outcome was already "committed" (the
                            # commit boundary had been passed when the first
                            # cancellation arrived), this second cancellation
                            # changes nothing about that - "committed" stays
                            # "committed", even though we no longer report it here
                            # explicitly in text.
                            raise
                        if outcome == "committed":
                            # "committed" means the commit boundary (the stop check
                            # under the gate's lock) was passed before the stop was
                            # set - it says NOTHING about whether the swap itself
                            # had finished when the cancellation landed. The gate
                            # records that order explicitly in
                            # `stop_set_at_commit_boundary`, so the message below
                            # states the boundary instead of a guessed sequence.
                            writes_since_scan.resolve_scan(baseline)
                            export = load_export(export_dir)
                            herkomst = _record_provenance(name, export, stop.manifest_hash)
                            stamped = _stamp(
                                Answer(question=f"verversen van {name}"),
                                export,
                            )
                            # The SAME seam every other read tool
                            # uses, not a second masking path - `render()` masks
                            # `data_target` (the twelfth name family) at
                            # 'beperkt'/'minimaal' exactly like the other eleven.
                            line = render(
                                stamped,
                                disclosure,
                                tool="status_ververs",
                                extra_names=names_from_export(export),
                                pseudonym_table_path=pseudonym_table_path,
                            ).splitlines()[-1]
                            if herkomst:
                                line = f"{herkomst}\n{line}"
                            if stop.stop_set_at_commit_boundary is False:
                                return (
                                    f"De scan van '{name}' is voltooid: de annulering kwam nadat de "
                                    f"commitgrens al was gepasseerd, dus de omwisseling is doorgegaan.\n{line}"
                                )
                            # Structurally unreachable while decide() only sets
                            # "committed" in the branch that just recorded False -
                            # but deliberately no guessing if that invariant ever
                            # breaks: "onbekend" is then the honest text.
                            return (
                                f"De scan van '{name}' is voltooid, maar onbekend is of de annulering "
                                f"voor of na de commitgrens aankwam.\n{line}"
                            )
                        # The worker lost the race (or has yet to decide, but `stop`
                        # is then already irreversibly True - see SwapGate.decide():
                        # that decision can then only become "aborted"). So here the
                        # cancellation IS passed on, never swallowed.
                        raise
                    except CollectError as exc:
                        # Deliberately NO mask_error: this is an intended outcome
                        # with information the caller needs, not an internal error.
                        # Deliberately NO unconditional "the previous data still
                        # applies": in the interrupted-swap window (_swap renames
                        # the live export to .vorig and then fails on the second
                        # rename, see the module docstring of collect.py) there is
                        # temporarily NO export at all. So this message promises no
                        # state this layer cannot guarantee - the data age in the
                        # next answer is the only place that really knows.
                        #
                        # Per design 2.2: the phased diagnosis.
                        # `phase_report` derives no phase from the error TEXT
                        # above - it reads either the collect script's own typed
                        # phase file or the artefacts this attempt actually
                        # produced. `exc.evidence_dir` (collect.py) names exactly
                        # the directory that holds THIS attempt's own data - the
                        # `.mislukt` slot `_preserve_as_failed` moved it to, or
                        # `None` when this attempt never got that far (a missing
                        # script, a concurrent scan, ...) - `phase_report` then
                        # honestly reports every phase as "niet vastgesteld"
                        # instead of guessing at a stale, unrelated directory.
                        #
                        # MEASURED: `export_dir.parent` -
                        # the original call here - is never that
                        # directory. `collect()`'s work directory is a temporary
                        # SIBLING of `export_dir` (`tempfile.mkdtemp(dir=
                        # export_dir.parent)`), renamed on failure to
                        # `<export_dir>.mislukt` or removed - never to
                        # `export_dir.parent` itself. Pointing there found
                        # nothing in production and reported every phase "niet
                        # vastgesteld" on every failed scan, regardless of what
                        # the script actually established - the silent empty
                        # outcome design chapter 2.1 forbids.
                        if disclosure is not Disclosure.FULL:
                            # One asymmetry
                            # worth naming: the failed-collector-script tail
                            # (`_short_report`, collect.py) is raw output of ANOTHER
                            # product, masked only for the three values this
                            # product knows as "of the target". `render()` cannot
                            # mask it - the thumbprint the appliance presented, a
                            # second address, an object name the export does not
                            # know sit in no name family - so it follows the same
                            # rule as the writing tools' registration gate and the
                            # unknown-target enumeration above: it exists only at
                            # 'volledig'. Classified reasons (a held lock, a
                            # timeout, an OS error KIND) carry no script output and
                            # pass through unchanged - the operator on 'minimaal'
                            # still learns WHY the scan did not run.
                            exc = exc.without_script_output()
                        diagnosis = phase_summary(phase_report(exc.evidence_dir, export_dir))
                        # 1.0.2: the failure is not a bare f-string any
                        # more. The error and the phase lines (both can carry
                        # text the collector wrote) go through the one text
                        # filter, line by line, and the product's own two stamp
                        # lines close the answer - after anything the collector
                        # may have printed that looks like them.
                        reden = safe_text(str(exc))
                        diagnose = "\n".join(safe_text(regel) for regel in diagnosis.splitlines())
                        kennis = _knowledge()
                        closing = Answer(
                            question=f"verversen van {name}",
                            knowledge_age_days=kennis.age_days,
                            knowledge_date=kennis.date,
                            data_age_reason=(
                                "deze scan leverde geen nieuwe gegevens; de leeftijd van de huidige"
                                " export staat in het volgende antwoord"
                            ),
                        ).stamp_lines()
                        return (
                            f"De scan van '{name}' is niet gelukt: {reden}\n"
                            f"{diagnose}\n"
                            "Of de vorige gegevens nog gelden, staat in de gegevensleeftijd "
                            "van het volgende antwoord.\n\n" + "\n".join(closing)
                        )
                    writes_since_scan.resolve_scan(baseline)
                    export = load_export(export_dir)
                    # Recorded BEFORE the answer is stamped, so the closing
                    # line already says where this export came from.
                    herkomst = _record_provenance(name, export, stop.manifest_hash)
                    stamped = _stamp(
                        Answer(question=f"verversen van {name}"),
                        export,
                    )
                    # Same seam as above, not a second masking path.
                    line = render(
                        stamped,
                        disclosure,
                        tool="status_ververs",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ).splitlines()[-1]
                    if herkomst:
                        return f"De scan van '{name}' is gelukt.\n{herkomst}\n{line}"
                    return f"De scan van '{name}' is gelukt.\n{line}"

                return await _guarded_async(ctx, work, "status_ververs", {"doelnaam": name})

        @server.tool()
        def status_cve_controle(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Toetst de build van de NetScaler aan de bekende securitybulletins uit het kennispakket, in twee lagen: zit de build onder de fix-build, en is de voorwaarde uit het bulletin in de configuratie aanwezig. Gebruik dit als de vraag is of een CVE deze NetScaler raakt."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    cve_check(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_cve_controle",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_cve_controle",
                )

            return _guarded(ctx, work, "status_cve_controle", {"doel": doel_clean})

        @server.tool()
        def status_overzicht(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Een overzicht van de NetScaler: build, HA-stand, aantal virtuele servers en hoe oud de gegevens zijn. Gebruik dit als eerste vraag, of als de vraag is hoe de NetScaler ervoor staat."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    overview(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_overzicht",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_overzicht",
                )

            return _guarded(ctx, work, "status_overzicht", {"doel": doel_clean})

        @server.tool()
        def status_update_advies(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Zegt welke build op deze NetScaler hoort: de huidige build, de vloer uit het kennispakket en de aangeboden build van de vendor, drie naast elkaar met hun herkomst en leeftijd. Gebruik dit als de vraag is welke build erop moet."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    update_advice(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_update_advies",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_update_advies",
                )

            return _guarded(ctx, work, "status_update_advies", {"doel": doel_clean})

        def _bundle_mb() -> int | None:
            """The size of the firmware bundle this window will install, in MB.

            The source is `onderhoud.firmwaremap`, read by
            `handelen.firmware_target_build()` - the SAME function that gives
            the runner its target build, so one directory has one policy: zero
            or more than one bundle is no target build and no size either.
            `None` (no `onderhoud`, or no unique bundle) hands over to
            `preflight.ASSUMED_BUNDLE_MB`, WITH THE ASSUMPTION NAMED in the
            answer, so nothing here silently guesses.
            """
            if onderhoud is None:
                return None
            try:
                return firmware_target_build(onderhoud.firmwaremap).mb or None
            except ActionError:
                return None

        def _free_var_mb_over_ssh(target):
            """(vrije MB op /var, leesgat) over SSH: the small read script
            next to the faserunner (`Invoke-GjkLiveMeting.ps1`), through the
            runner's own transport - the pinned host key, the credential from
            Windows Credential Manager, `df -k /var` parsed in ONE place
            (`Get-GjkVrijeRuimteVar`). A separate PowerShell process, like the
            collector route: this process opens no socket.

            Fail closed in every direction: no script, a process that could
            not start, the time limit, a non-zero exit code, anything but one
            whole number - each a ReadGap with its reason, and never a second
            attempt through the collector.

            The third value says whether a read process really ran (since
            1.0.2): a missing script, an invalid pin or a process that did
            not start is "niet gelezen", never "live gelezen"."""
            script = sibling_script(onderhoud, LIVE_MEASURE_SCRIPT)
            if not script.is_file():
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_ROUTE_SSH,
                        reason=(
                            f"het meetscript {LIVE_MEASURE_SCRIPT} staat niet naast de faserunner; er is niet live gelezen"
                        ),
                    ),
                    False,
                )
            try:
                arguments = build_live_measure_arguments(target, onderhoud, forbidden_addresses=forbidden_addresses)
            except ValueError:
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_ROUTE_SSH,
                        reason="de gepinde hostsleutel van dit doel is geen geldige vingerafdruk; er is niet live gelezen",
                    ),
                    False,
                )
            # 1.1: `typed_runner`, so a measurement that did not start says
            # why by type (`_not_started_sentence`), never by the text.
            runner = live_run or typed_runner
            try:
                code, stdout, _stderr = runner(script_command(script, arguments), LIVE_MEASURE_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_ROUTE_SSH,
                        reason=(
                            f"de live lezing over SSH overschreed de tijdslimiet van {LIVE_MEASURE_TIMEOUT_S} seconden"
                            " en is afgebroken"
                        ),
                    ),
                    True,
                )
            except ActionError as exc:
                sentence = _not_started_sentence(exc)
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_ROUTE_SSH,
                        reason=(
                            "de live lezing over SSH kon niet gestart worden"
                            if sentence is None
                            else f"de live lezing over SSH kon niet gestart worden: {sentence}"
                        ),
                    ),
                    False,
                )
            vrij, reden = free_space_from_script(code, stdout)
            if vrij is None:
                return None, ReadGap(source=FREE_SPACE_ROUTE_SSH, reason=_scrub_ssh_text(reden, target)), True
            return vrij, None, True

        def _free_var_mb(gekozen: str = ""):
            """(vrije MB op /var, leesgat, route) - the one LIVE read of this
            product's reading tools.

            `gekozen` is the target the caller named with `doel` (already
            proven to be the target of the export); without it the target
            can only be implied, which works with exactly one configured
            target.

            The route is chosen on CONFIGURATION, never on failure: over SSH
            when `onderhoud` is configured and the target carries a pinned
            host key (`_free_var_mb_over_ssh`), otherwise the collector
            (`collect.read_single_resource`, the SAME separate process a scan
            starts, with the SAME `doelen` credential). No silent cascade: a
            failed SSH read is a read gap, not a reason to try the other
            route. Either way the tool itself opens no socket - a separate
            process does. This is the second of the two documented exceptions
            (design 2.10 row 13, 3.1); a third name on that list is a change
            of the design.

            Every route out of here that is not a number is a ReadGap with the
            reason named - never a value, and never a silent green. The tool is
            NOT withheld when this fails: eight of the nine checks are still
            answerable.
            """
            if not targets:
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_RESOURCE,
                        reason=(
                            "er is geen doel ingesteld, dus de vrije ruimte is niet live te lezen;"
                            " de andere acht toetsen komen wel uit de export"
                        ),
                    ),
                    None,  # no read ran, so no route to name (1.0.2)
                )
            if not gekozen and len(targets) > 1:
                # Without `doel` (one pre-flight answer about the appliance
                # this export describes), with more than one configured target
                # there is no way to establish WHICH appliance to measure.
                # Naming that beats measuring the wrong box.
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_RESOURCE,
                        reason=(
                            f"er zijn {len(targets)} doelen ingesteld en deze toets krijgt geen"
                            " doelnaam mee; welke appliance gemeten moet worden is niet vast te"
                            " stellen"
                        ),
                    ),
                    None,  # no read ran, so no route to name (1.0.2)
                )
            target = targets[gekozen] if gekozen else next(iter(targets.values()))
            if onderhoud is not None and target.ssh_hostsleutel_vingerafdruk:
                vrij, gap, ran = _free_var_mb_over_ssh(target)
                return vrij, gap, FREE_SPACE_ROUTE_SSH if ran else None
            if collect_script is None:
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_RESOURCE,
                        reason=(
                            "er is geen verzamelscript ingesteld, dus deze server kan de vrije ruimte niet live lezen"
                        ),
                    ),
                    None,  # no read ran, so no route to name (1.0.2)
                )
            if not Path(collect_script).is_file():
                # 1.0.2: checked here as well as in read_single_resource,
                # so a missing script is "niet gelezen" without a route.
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_RESOURCE,
                        reason="het verzamelscript is niet gevonden; er is niet live gelezen",
                    ),
                    None,
                )
            # Two minutes, deliberately far below the 900 s of a full scan
            # (collect.collect): this is ONE resource, and a pre-flight that
            # hangs for a quarter of an hour on it would hold up the eight
            # checks that need no appliance at all. A timeout is a ReadGap
            # here, never an exception - see read_single_resource.
            row, gap, ran = read_single_resource(
                target, FREE_SPACE_RESOURCE, collect_script, timeout_s=LIVE_MEASURE_TIMEOUT_S, run=run
            )
            if gap is not None:
                # 1.0.2: a process that never started names no route.
                return None, gap, FREE_SPACE_ROUTE_COLLECTOR if ran else None
            raw = row.get(FREE_SPACE_FIELD)
            try:
                # A NITRO statistic arrives as text. `int(...)` is the shape
                # gate: anything that is not a whole number of MB is an absence
                # with a reason, never a figure this product invented.
                return int(str(raw).strip()), None, FREE_SPACE_ROUTE_COLLECTOR
            except (AttributeError, TypeError, ValueError):
                return (
                    None,
                    ReadGap(
                        source=FREE_SPACE_RESOURCE,
                        reason=(
                            f"het veld {FREE_SPACE_FIELD} ontbreekt in de live lezing of draagt"
                            " geen geheel getal; de vrije ruimte is niet vast te stellen"
                        ),
                    ),
                    FREE_SPACE_ROUTE_COLLECTOR,
                )

        @server.tool()
        async def status_update_preflight(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Loopt negen toetsen na die een upgrade binnen 14.1 kunnen tegenhouden: licentie, classic-markers, HA-stand, drift tussen running en saved, certificaathorizon, build en tak, vormfactor, vrije ruimte op /var en het terugrolpad. De vrije ruimte wordt live gelezen in een apart proces: over SSH als onderhoud is ingesteld en het doel een gepinde hostsleutel heeft, anders via hetzelfde verzamelscript als de scan; dit is geen vendor-precheck. Gebruik dit voordat een onderhoudsvenster gepland wordt."""
            doel_clean = _normalize(doel)

            async def work():
                export, knowledge = _load_for(doel_clean)
                # `_load_for` has proven a given `doel` is the export's own
                # target, so that is the appliance to measure live.
                gekozen = export.target_name if doel_clean else ""
                vrij, gap, route = await asyncio.to_thread(_free_var_mb, gekozen)
                answer = _stamp(
                    preflight_answer(export, knowledge, vrij, _bundle_mb(), gap, free_space_route=route),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_update_preflight",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_update_preflight",
                )

            return await _guarded_async(ctx, work, "status_update_preflight", {"doel": doel_clean})

        @server.tool()
        def status_gezondheid(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Wat er DOWN stond op het moment van de scan: tellingen en namen per familie, met storing en dekkingsuitspraak strikt gescheiden. Dit is een momentopname uit de export met een gegevensleeftijd, geen bewaking."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    health_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_gezondheid",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_gezondheid",
                )

            return _guarded(ctx, work, "status_gezondheid", {"doel": doel_clean})

    if "dienst" in chapters:

        @server.tool()
        def dienst_status(dienst: str, doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk dienst. De toestand van een dienst (virtuele server) en van elk lid van de gebonden servicegroup, zoals de appliance die rapporteert. Gebruik dit als de vraag is hoe een dienst of een webserver ervoor staat."""
            name = _normalize(dienst)
            doel_clean = _normalize(doel)

            def work():
                clean = _require_nonempty(name, "dienst mag niet leeg zijn")
                export, knowledge = _load_for(doel_clean)
                answer = service_status(export, knowledge, clean)
                answer = _stamp(answer, export)
                # Same reasoning as certificaat_wat_breekt_er above: the
                # queried name travels as `caller_name`, separately from the
                # structural export names, so a real dienst/servicegroup/
                # member name is masked exactly as before while a
                # caller-invented one may never be treated as a real
                # appliance name.
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="dienst_status",
                        extra_names=names_from_export(export),
                        caller_name=clean,
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "dienst_status",
                )

            return _guarded(ctx, work, "dienst_status", {"dienst": name, "doel": doel_clean})

        @server.tool()
        def dienst_keten(dienst: str = "", doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk dienst. De keten van een dienst, van VIP tot backend: ingang, backendgroep en leden, met per keten of hij compleet is, waar het gat zit of dat hij niet vast te stellen is. Laat het argument leeg voor alle ketens. Losse objecten staan in een apart blok. Dit bewijst niet dat het verkeer ook echt zo loopt."""
            wanted = _normalize(dienst)
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    service_chain(export, knowledge, wanted),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="dienst_keten",
                        extra_names=names_from_export(export),
                        caller_name=wanted or None,
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "dienst_keten",
                )

            return _guarded(ctx, work, "dienst_keten", {"dienst": wanted, "doel": doel_clean})

    if "kennis" in chapters:

        @server.tool()
        def kennis_uitleg(begrip: str, *, ctx: Context) -> str:
            """Hoofdstuk kennis. Legt een NetScaler-begrip uit vanuit het geladen kennispakket, of zegt dat het er niet in staat. Gebruik dit als je een term uit een antwoord wilt begrijpen; verzin nooit zelf een uitleg."""
            term = _normalize(begrip)

            def work():
                clean = _require_nonempty(term, "begrip mag niet leeg zijn")
                # Knowledge-only read: this tool never touches the export, so
                # it calls _knowledge() directly instead of the shared
                # _load() (which also loads the export, for the tools that DO
                # need it): one read fewer that this tool has no use for.
                knowledge = _knowledge()
                # A REFUSED package is not an empty one - the same rule cve.py
                # already applies for status_cve_controle. A refused Knowledge
                # carries glossary={}, so without this branch every package the
                # reader turns down (no `cve` key, past the depth or byte
                # ceiling, over the text ceiling) answered "staat niet in het
                # kennispakket" for a term that IS in the file, and threw
                # `reason` away: a silent green.
                # is_file() draws the line between "there is no package" - the
                # optional absence the reader documents, whose reason names the
                # configured path and which keeps the branch below and its
                # pinned test - and "there IS a package and it was refused",
                # which is what gets its reason named here. The reason then
                # only ever describes knowledge-package content, the very thing
                # this tool exists to hand out, so it needs no disclosure seam.
                if knowledge.missing and knowledge_path.is_file():
                    reason = knowledge.reason.strip() or "reden onbekend"
                    # kennis_uitleg is the one reading tool outside the
                    # Answer.to_text() seam (answer._safe / render()) that
                    # never masks names to begin with, so it has no disclosure
                    # levels to switch on - but `reason` is still untrusted
                    # package content (built from unknown keys, unknown
                    # fields and raw bulletin ids, see knowledge.py) and needs
                    # the SAME cap and newline flattening every other reading
                    # tool gets for free through to_text(). safe_text() is
                    # that same function, made public for this call site.
                    #
                    # A REFUSED package carries no age line here - there IS
                    # no readable knowledge to date, only a reason it could
                    # not be read, and that reason is already the honest
                    # answer. This branch stays exactly as it was; only the
                    # two branches below (a loaded-or-truly-absent package)
                    # gain the knowledge-base age line.
                    return f"Het kennispakket is onbruikbaar; er valt niets uit te leggen. Reden: {safe_text(reason)}."
                # Case-insensitive fallback built ONCE per call, over every
                # key. The older `.get(clean.lower())` compared the LOWERED question only
                # against the ORIGINAL keys, so it matched a mixed-case
                # package key (e.g. "Servicegroup") only by accident, never
                # by the case-insensitive rule intended.
                lowered_glossary = {k.lower(): v for k, v in knowledge.glossary.items()}
                entry = knowledge.glossary.get(clean) or lowered_glossary.get(clean.lower())
                if not entry:
                    # The unresolved term travels through the SAME
                    # disclosure seam every other
                    # reading tool uses for a name it cannot resolve
                    # (disclosure.py `_limit()`/`render()`, invented_name ->
                    # _UNKNOWN_NAME_IN_QUESTION). In 'volledig' the term the
                    # caller typed may be shown - it is a public glossary
                    # lookup key, not export data. In 'beperkt'/'minimaal' it
                    # is replaced by that SAME fixed placeholder, never a
                    # second, invented one and never the typed term itself:
                    # echoing it verbatim here would defeat the whole point
                    # of those levels the moment a caller types a real
                    # appliance object name as `begrip`.
                    # 1.0.2: the echo goes through the filter and the name limit.
                    shown = safe_name(clean) if disclosure is Disclosure.FULL else _UNKNOWN_NAME_IN_QUESTION
                    # `knowledge.version` is capped at the source
                    # (knowledge.py) but not type-checked there, and this is
                    # the NOT-FOUND branch: the common case, at every
                    # disclosure level. safe_text() bounds and flattens it
                    # here too, the same defense in depth `reason` gets above.
                    version = safe_text(knowledge.version) if knowledge.version else "onbekend"
                    # kennis_uitleg gets the knowledge-base age line too, so
                    # "elk antwoord meldt zijn ouderdom" holds for this tool
                    # as well - only the kennisbasis-regel applies (this tool
                    # reads no export, so the data/export line never fits
                    # it). Same text as every other answer's footer:
                    # knowledge_age_line() is the one builder
                    # Answer.stamp_lines() also calls, so the two renderings
                    # cannot drift apart. knowledge.date/knowledge.age_days
                    # are already None for a truly absent package (no file at
                    # all), which renders the same "ONBEKEND" text every
                    # other tool shows for that case.
                    return (
                        f"'{shown}' staat niet in het kennispakket (versie {version})."
                        f"\n\n{knowledge_age_line(knowledge.date, knowledge.age_days)}"
                    )
                # `entry` is a glossary value: already capped at 8192 by
                # knowledge.py, but a bare newline inside it survives that
                # cap. safe_text() flattens it, same as every value that goes
                # through Answer.to_text() - kennis_uitleg has no Answer to
                # route it through, so it calls the same function directly.
                # The knowledge-base age line below is the same reuse as the
                # NOT-FOUND branch above - see that branch's comment.
                return f"{safe_name(clean)}: {safe_text(entry)}\n\n{knowledge_age_line(knowledge.date, knowledge.age_days)}"

            return _guarded(ctx, work, "kennis_uitleg", {"begrip": term})

    if "onderhoud" in chapters and onderhoud is not None:

        def _soak_hours() -> int:
            """`onderhoud.soak_uren` when `onderhoud` is configured, else
            `MINIMUM_SOAK_HOURS`.

            A later fix: `onderhoud` landed on this
            branch, and `onderhoud_upgrade_fase`/`onderhoud_upgrade_stand`
            both already read `onderhoud.soak_uren` directly - this function
            kept hardcoding `MINIMUM_SOAK_HOURS` unconditionally, from
            BEFORE that section existed, so one chapter reported two
            different soak windows out of its three tools the moment
            `onderhoud.soak_uren` was configured above the minimum.
            `onderhoud_upgrade_plan` needs no `onderhoud` section to
            register at all (unlike the other two), so the minimum stays
            the honest fallback when it is absent.
            """
            return onderhoud.soak_uren if onderhoud is not None else MINIMUM_SOAK_HOURS

        @server.tool()
        def onderhoud_upgrade_plan(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk onderhoud. Stelt het plan op voor een upgrade binnen 14.1: de zeven fasen, de HA-volgorde (secondary eerst), het soakvenster, het terugrolpad per fase en per fase de poort die open moet. Deze tool leest alleen en wijzigt niets. Gebruik dit als een onderhoudsvenster voorbereid moet worden."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    upgrade_plan(export, knowledge, _soak_hours(), doelbuild=_firmware_bundle_or_reason()),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="onderhoud_upgrade_plan",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "onderhoud_upgrade_plan",
                )

            return _guarded(ctx, work, "onderhoud_upgrade_plan", {"doel": doel_clean})

        if onderhoud is not None:

            def _stand_target(gegeven: str) -> str:
                """Which target's ledger `onderhoud_upgrade_stand` reads: the
                argument if given, or the sole CONFIGURED target when there
                is exactly one - the same "one target needs no doel"
                convenience the writing tools give (`_target_for`), sourced
                from `targets` (the configured doelen) and not from the
                allowlist: a read tool is not gated by write permission, so
                the allowlist may legitimately be empty while a target still
                exists to read a ledger for.

                A GIVEN name is
                CONSTRAINED to `targets` instead of returned verbatim. An
                unconfigured name used to sail through unchanged into
                `_write_names()`, whose allowlist half
                (`allowlist.per_target.get(doelnaam, {})`) then quietly
                returns nothing for a target it does not know - not a
                crash, a NARROWER mask set than a real target on this
                server gets, degrading to `names_from_export()` alone. The
                message deliberately does not echo the given value back
                (the same restraint `Refusal`'s own "doel-onbekend" text
                already applies for the writing tools, `handelen.py`).

                A given name goes through `_resolve_doel`, the resolver the
                export-backed reading tools and the writing path share: at
                'beperkt' a pseudonym out of `status_doelen` is a valid
                `doel` here too."""
                gekozen = gegeven.strip()
                namen = tuple(sorted(targets))
                if gekozen:
                    echt = _resolve_doel(gekozen, targets)
                    if echt is None:
                        raise ToolError(ONBEKEND_DOEL_TEXT)
                    return echt
                if len(namen) == 1:
                    return namen[0]
                raise ToolError("geef doel op: er is niet precies een doel ingesteld om zonder doel te kiezen")

            @server.tool()
            def onderhoud_upgrade_stand(doel: str = "", run: str = "", *, ctx: Context) -> str:
                """Hoofdstuk onderhoud. Leest het ledger van een upgraderun en geeft per fase de poorten met hun uitkomst, plus hoe oud de laatste regel is. Zonder run: de laatste run op dat doel. Deze tool leest alleen en wijzigt niets. Gebruik dit om te zien hoe een fase is afgelopen."""
                doel_clean = _normalize(doel)
                run_clean = _normalize(run)

                def work():
                    gekozen_doel = _stand_target(doel_clean)
                    if run_clean and not is_safe_run_name(run_clean):
                        raise ToolError("run is geen geldige run-naam")
                    # `_rows_for_target` needs a path only to find the
                    # ledgermap directory - the file it names need not exist
                    # (same idiom as the cross-tool phase gate above).
                    # STRICT: a directory this tool cannot read is not an
                    # empty ledger - a read tool that cannot read its
                    # evidence must say so, never report "niets gevonden".
                    #
                    # `read_ledger()`
                    # reports a skipped, corrupt LINE only via
                    # `warnings.warn(RuntimeWarning)` - nothing captured that
                    # turns into something an operator can see. Turned into
                    # a `ReadGap` below: a ledger with corrupt rows must not
                    # read byte-identical to a clean one.
                    #
                    # This used to be
                    # `warnings.catch_warnings(record=True)` wrapped around
                    # the call below - process-global state, not
                    # thread-safe. `status_ververs` runs `collect()` on a
                    # SEPARATE thread (`asyncio.to_thread`); a warning
                    # raised there while this window happened to be open
                    # was captured HERE and rendered as false evidence
                    # about the LEDGER, while being suppressed at its own
                    # origin - and an argument-less `RuntimeWarning` raised
                    # in that same window blanked `overgeslagen` into a
                    # `ReadGap.__post_init__` crash, masked by `_guarded()`
                    # into the generic error. `skipped` is a plain list,
                    # local to this call: `read_ledger()` (via
                    # `_rows_for_target()`) appends to it directly, nothing
                    # global to race and nothing to filter by category.
                    skipped: list = []
                    try:
                        rijen = _rows_for_target(
                            onderhoud.ledgermap / "_.jsonl",
                            gekozen_doel,
                            strict=True,
                            skipped=skipped,
                        )
                    except LedgerUnreadable as exc:
                        raise ToolError(f"{exc}, dus de stand van dit doel is niet vast te stellen") from None
                    # The reason used to
                    # be the skipped lines' own warning text verbatim -
                    # `f"read_ledger: regel {n} in {path} ..."` - putting
                    # the ABSOLUTE ledger path and a line number into an
                    # operator-facing answer, while `LedgerUnreadable` two
                    # lines above deliberately reports only
                    # `type(exc).__name__` (`upgrade_gate.py`) and
                    # `mask_error` exists precisely to keep internals like a
                    # path out of a customer's answer. Only the COUNT of
                    # unreadable lines travels here now.
                    lees_gaten = (
                        [
                            ReadGap(
                                source="ledger",
                                reason=(
                                    "1 ledgerregel kon niet gelezen worden"
                                    if len(skipped) == 1
                                    else f"{len(skipped)} ledgerregels konden niet gelezen worden"
                                ),
                            )
                        ]
                        if skipped
                        else []
                    )
                    # Zonder `run`: de rij met de nieuwste LEESBARE tijd wijst
                    # de laatste run aan - nooit `rijen[-1]["run"]` zelf:
                    # dat crashte op
                    # een rij zonder `run`-sleutel, en `_rows_for_target`'s
                    # eigen sortering (`upgrade_gate._row_time`) zet een rij
                    # met een onleesbare `tijd` LAATST zonder dat dat de echt
                    # laatste maakt - `latest_run_name()` slaat zo'n rij
                    # over in plaats van hem stilzwijgend als "de laatste
                    # run" te lezen.
                    gekozen_run = run_clean or latest_run_name(rijen)
                    regels = tuple(r for r in rijen if r.get("run") == gekozen_run) if gekozen_run else ()
                    # Het soakvenster bindt het DOEL, over elk
                    # runbestand heen - net als de OPEN-RUN- en SOAK-check
                    # van `onderhoud_upgrade_fase` hierboven. `regels` is al
                    # tot de gekozen RUN beperkt (voor de fase-bevindingen);
                    # `target_lines=rijen` geeft `stand_answer()` de
                    # doelbrede rijen voor de soaklezing apart mee, zodat een
                    # retry-run B de soak_open-regel van run A niet mist.
                    answer = stand_answer(
                        regels,
                        datetime.now(UTC),
                        onderhoud.soak_uren,
                        target_lines=rijen,
                        read_gaps=lees_gaten,
                    )
                    # De twee argumenten van deze tool
                    # (`doel`/`run`) lossen allebei impliciet op - dus zegt
                    # het antwoord zelf welke run gekozen is.
                    #
                    # `gekozen_run` is
                    # LEDGER content the moment it is not `run_clean` (the
                    # CALLER-supplied value, already `is_safe_run_name()`-
                    # checked above) - `latest_run_name(rijen)` reads it
                    # straight off a ledger row's own `run` field with no
                    # check at all, and it went into `outcome=` unbounded
                    # and unsanitised: one hostile row forged an extra
                    # finding line (or, at any length, blew past every
                    # other bound this answer respects). `_bounded_run_
                    # echo()` (upgrade.py, next to `_bounded`/`_bounded_
                    # or()`) makes it single-line and capped BEFORE it
                    # reaches the `Finding` - `gekozen_run` itself stays
                    # untouched for the `regels` filter above, which must
                    # match the ledger's own raw value exactly.
                    if gekozen_run:
                        run_finding = Finding(
                            subject="run",
                            outcome=_bounded_run_echo(gekozen_run),
                            certainty=Certainty.ESTABLISHED,
                            evidence=(AANROEP_ARGUMENT_TEXT if run_clean else RUN_LAATSTE_OP_DOEL_TEXT),
                            subject_is_name=False,
                        )
                    else:
                        run_finding = Finding(
                            subject="run",
                            outcome=RUN_NIET_BEPAALD_TEXT,
                            certainty=Certainty.NOT_ESTABLISHED,
                            evidence=RUN_GEEN_LEESBARE_TIJD_TEXT,
                            reason=RUN_GEEN_LEESBARE_TIJD_TEXT,
                            subject_is_name=False,
                        )
                    # `_stamped()` below
                    # stamps `doel:` in the FOOTER from `export.target_name`
                    # - ONE value per server, whichever target was last
                    # SCANNED into `export_dir`, not the `doel` THIS CALL
                    # resolved above. On a server configured for more than
                    # one target, `onderhoud_upgrade_stand(doel="lab-03")`
                    # reads lab-03's ledger while the footer can still say
                    # "doel: lab-02" - a body finding names the target this
                    # answer actually reads, correctly, regardless of what
                    # the footer says.
                    doel_finding = Finding(
                        subject="doel",
                        outcome=gekozen_doel,
                        certainty=Certainty.ESTABLISHED,
                        evidence=(AANROEP_ARGUMENT_TEXT if doel_clean else DOEL_ENIGE_GECONFIGUREERDE_TEXT),
                        subject_is_name=False,
                    )
                    # An undecided start on this target is not in the ledger
                    # at all - it lives in this server's register - so it gets
                    # its own finding, appended after the ledger's own lines.
                    blocking, lapsed = undecided_starts.check(gekozen_doel, datetime.now(UTC), rijen)
                    register_findings = [
                        *([_undecided_stand_finding(blocking)] if blocking is not None else []),
                        *([_undecided_lapse_finding(lapsed)] if lapsed is not None else []),
                    ]
                    answer = replace(
                        answer,
                        findings=[doel_finding, run_finding, *answer.findings, *register_findings],
                    )
                    # `extra_names=_write_names(gekozen_doel)`: ledger evidence
                    # can carry a real object name this target's own writing
                    # tools already form (a backup name, say) - the SAME
                    # masking set `_rendered()` gives the FASE GESTART answer
                    # for this target, so a name is not masked in one answer
                    # about this target's upgrade and echoed raw in the next.
                    # `_stamped()`: the same two closing stamps
                    # every OTHER reading tool carries - this tool builds its
                    # Answer straight from the ledger, never through
                    # `_load()`, so without this call the footer said "geen
                    # kennispakket geladen" even when one was, and "doel:
                    # niet vastgelegd" even though a target was chosen above.
                    return render(
                        _stamped(answer),
                        disclosure,
                        tool="onderhoud_upgrade_stand",
                        extra_names=_write_names(gekozen_doel) + _via_pseudoniem(doel_clean, gekozen_doel),
                        pseudonym_table_path=pseudonym_table_path,
                    )

                return _guarded(
                    ctx,
                    work,
                    "onderhoud_upgrade_stand",
                    {"doel": doel_clean, "run": run_clean},
                )

            if "rapport" in chapters:

                @server.tool()
                def rapport_na_upgrade(doel: str = "", run: str = "", *, ctx: Context) -> str:
                    """Hoofdstuk rapport. Zet de stand van voor en na een upgrade naast elkaar: per bron voor en na, het CVE-oordeel op de nieuwe build, de extra stap die het bulletin na de upgrade vraagt als eigen controle, en het genormaliseerde configuratie-anker met het aantal uitgesloten blob-regels per soort. Gebruik dit na een upgrade om te zien wat er veranderd is."""
                    doel_clean = _normalize(doel)
                    run_clean = _normalize(run)

                    def work():
                        # Standalone as far as it can
                        # stand - the comparison this needs is not wired in on
                        # this branch, so this tool resolves only ONE
                        # target per call, the same "one configured target
                        # needs no argument" convention `onderhoud_upgrade_
                        # stand` uses (`_stand_target`, shared with it
                        # above).
                        #
                        # A later fix: this tool's own
                        # pinned surface used to carry NO `doel` argument
                        # at all, while `_stand_target("")` below refused
                        # on a multi-target server with "geef doel op..." -
                        # an instruction the caller had no argument to
                        # follow. `doel` is now on the surface, for
                        # consistency with `onderhoud_upgrade_stand`
                        # (this raises the pinned tool-surface count in
                        # test_product_surface.py, deliberately).
                        gekozen_doel = _stand_target(doel_clean)
                        if run_clean and not is_safe_run_name(run_clean):
                            raise ToolError("run is geen geldige run-naam")
                        skipped: list = []
                        try:
                            rijen = _rows_for_target(
                                onderhoud.ledgermap / "_.jsonl",
                                gekozen_doel,
                                strict=True,
                                skipped=skipped,
                            )
                        except LedgerUnreadable as exc:
                            raise ToolError(f"{exc}, dus het rapport na de upgrade is niet vast te stellen") from None
                        lees_gaten = (
                            [
                                ReadGap(
                                    source="ledger",
                                    reason=(
                                        "1 ledgerregel kon niet gelezen worden"
                                        if len(skipped) == 1
                                        else f"{len(skipped)} ledgerregels konden niet gelezen worden"
                                    ),
                                )
                            ]
                            if skipped
                            else []
                        )
                        gekozen_run = run_clean or latest_run_name(rijen)
                        regels = tuple(r for r in rijen if r.get("run") == gekozen_run) if gekozen_run else ()
                        # The ledger above is the chosen target's; the
                        # export is the server's ONE export. That export
                        # must describe the chosen target - given, or the
                        # one configured target when `doel` is left out -
                        # the same check (`_export_is_van`) every other
                        # export-backed reading tool makes for a given
                        # `doel`, or the CVE verdict and the extra step
                        # would describe another (or an unknown) appliance
                        # as this one after its upgrade. `gekozen_doel` is
                        # already resolved and never empty here.
                        export, knowledge = _load()
                        _export_is_van(gekozen_doel, export)
                        # `before=None`: block 1 is not wired in on
                        # this branch - `report_after_upgrade()` accepts
                        # and ignores it today; this is the exact seam
                        # `compare.compare_answer()`/`retention.newest_kept()`
                        # fill once wired in (see docs/klant/OPENSTAANDE-METINGEN.md).
                        answer = report_after_upgrade(None, export, knowledge, regels)
                        if gekozen_run:
                            run_finding = Finding(
                                subject="run",
                                outcome=_bounded_run_echo(gekozen_run),
                                certainty=Certainty.ESTABLISHED,
                                evidence=(AANROEP_ARGUMENT_TEXT if run_clean else RUN_LAATSTE_OP_DOEL_TEXT),
                                subject_is_name=False,
                            )
                        else:
                            run_finding = Finding(
                                subject="run",
                                outcome=RUN_NIET_BEPAALD_TEXT,
                                certainty=Certainty.NOT_ESTABLISHED,
                                evidence=RUN_GEEN_LEESBARE_TIJD_TEXT,
                                reason=RUN_GEEN_LEESBARE_TIJD_TEXT,
                                subject_is_name=False,
                            )
                        answer = replace(
                            answer,
                            findings=[run_finding, *answer.findings],
                            read_gaps=[*answer.read_gaps, *lees_gaten],
                        )
                        return _with_explanation(
                            render(
                                _stamp(
                                    answer,
                                    export,
                                ),
                                disclosure,
                                tool="rapport_na_upgrade",
                                extra_names=_write_names(gekozen_doel) + _via_pseudoniem(doel_clean, gekozen_doel),
                                pseudonym_table_path=pseudonym_table_path,
                            ),
                            knowledge,
                            "rapport_na_upgrade",
                        )

                    return _guarded(
                        ctx,
                        work,
                        "rapport_na_upgrade",
                        {"doel": doel_clean, "run": run_clean},
                    )

    if "status" in chapters:

        @server.tool()
        def status_namen(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk status. Welke namen deze NetScaler kent, per familie: loadbalancing-, contentswitching- en Gateway-vservers, servicegroups, services en certificaten. Gebruik dit als je een naam nodig hebt voor een andere vraag; verzin nooit zelf een naam."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    entity_names(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_namen",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_namen",
                )

            return _guarded(ctx, work, "status_namen", {"doel": doel_clean})

        def _ledger_view(namen: tuple[str, ...]) -> LedgerView:
            """The ledger rows of every target, read strictly: a ledger
            directory this server cannot read is not an empty one. The
            skipped-line count covers every run file in the directory, so it
            is the same for every target and counted once."""
            if onderhoud is None:
                return LedgerView(configured=False)
            rows: dict[str, tuple] = {}
            skipped_most = 0
            try:
                for naam in namen:
                    skipped: list = []
                    rows[naam] = _rows_for_target(onderhoud.ledgermap / "_.jsonl", naam, strict=True, skipped=skipped)
                    skipped_most = max(skipped_most, len(skipped))
            except LedgerUnreadable:
                # The exception's own text names the local ledger path; the
                # answer gets this product's fixed sentence instead.
                return LedgerView(configured=True, unreadable=True)
            return LedgerView(configured=True, rows=rows, skipped=skipped_most)

        @server.tool(description=STATUS_DOELEN_DESCRIPTION)
        def status_doelen(*, ctx: Context) -> str:
            """Which targets this server knows (the public MCP description is
            the pinned module constant above).

            Always registered in the `status` chapter: it reads the targets
            file and the allowlist this server was built with, the manifest
            of the export and the ledger - all on disk, never a socket. The
            answer is built in `doelen.py` out of a target's name, address
            and whether a host key is pinned; the credential target and the
            fingerprints are never read into it. At 'beperkt' the target
            names and addresses are masked like every other name, through
            the one seam (`render()`) - and the pseudonym a caller reads
            here is what it hands back as `doel` (`_resolve_doel`).
            """

            def work():
                namen = target_names(targets, allowlist)
                if not namen:
                    return GEEN_DOEL_TEXT
                export, knowledge = _load()
                # Granted in the allowlist is not the same as callable: only
                # the writing tools this server REALLY registered count as
                # offered (`writing_allowed` is assigned further down in
                # build_server(), before any tool can answer).
                offered = frozenset(tool for tool in WRITE_TOOLS if writing_allowed and _tool_is_registered(tool))
                today = datetime.now(UTC).date()
                answer = _stamp(
                    targets_answer(
                        targets=targets,
                        allowlist=allowlist,
                        offered=offered,
                        export=export,
                        ledger=_ledger_view(namen),
                        today=today,
                        knowledge=knowledge,
                    ),
                    export,
                    today,
                )
                adressen = tuple(target.address for target in targets.values())
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="status_doelen",
                        extra_names=names_from_export(export) + namen + adressen,
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "status_doelen",
                )

            return _guarded(ctx, work, "status_doelen", {})

    if "rapport" in chapters:

        @server.tool()
        def rapport_dekking(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk rapport. Hoe compleet dit antwoord is: per bron of hij gelezen is, welke bronnen mislukten, geweigerd werden of ontbraken, en of de kruiscontrole op de bindingen rondkwam. Gebruik dit als je wilt weten wat dit product NIET heeft kunnen lezen."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    coverage_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="rapport_dekking",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "rapport_dekking",
                )

            return _guarded(ctx, work, "rapport_dekking", {"doel": doel_clean})

        @server.tool()
        def rapport_vergelijk(mapA: str, mapB: str, modus: str = "run-diff", *, ctx: Context) -> str:
            """Hoofdstuk rapport. Vergelijkt twee exportmappen in een van vier modi: HA-parity (HA-pariteit: primary tegenover secondary), drift (nu tegenover een goedgekeurde baseline), run-diff (dezelfde doos op twee momenten) of pre/post (rond een wijziging). Configuratieverschillen, standverschillen en dekkingsverschillen staan in drie gescheiden blokken. Welke van de twee standen goed is, zegt dit antwoord niet - dat is een menselijk oordeel."""
            left_name, right_name, mode = _normalize(mapA), _normalize(mapB), _normalize(modus)

            def work():
                _require_nonempty(left_name, "mapA mag niet leeg zijn")
                _require_nonempty(right_name, "mapB mag niet leeg zijn")
                if mode not in COMPARE_MODES:
                    # Preflight ruling: refused WITHOUT echoing the supplied
                    # value - only the four valid modes are named, the same
                    # discipline `_inside_export_root()` applies to a
                    # supplied mapA/mapB. `compare.compare_exports()` itself
                    # DOES echo the value in its own ValueError - a fact
                    # for a programmatic caller, not for this client-facing
                    # text - so this checks MODES here rather than letting
                    # that exception reach `_guarded()` unchecked.
                    raise ToolError("onbekende vergelijkingsmodus; geldig is: " + ", ".join(COMPARE_MODES))
                left = load_export(_inside_export_root(left_name))
                right = load_export(_inside_export_root(right_name))
                knowledge = _knowledge()
                answer = _stamp(
                    compare_answer(left, right, knowledge, mode),
                    left,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="rapport_vergelijk",
                        extra_names=names_from_export(left) + names_from_export(right),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "rapport_vergelijk",
                )

            return _guarded(ctx, work, "rapport_vergelijk", {"mapA": left_name, "mapB": right_name, "modus": mode})

        @server.tool()
        def rapport_wat_is_er_veranderd(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk rapport. Wat er veranderd is sinds de vorige scan van dit doel: dezelfde vergelijking als rapport_vergelijk in de modus run-diff, met de twee mappen zelf gekozen. Is er geen bewaarde vorige export, dan zegt het antwoord dat er niets te vergelijken is - niet dat er geen verschillen zijn."""
            doel_clean = _normalize(doel)

            def work():
                gekozen = _gekozen_doel(doel_clean)
                previous, current_dir = two_newest(export_dir)
                knowledge = _knowledge()
                current = load_export(current_dir)
                # This tool reads the export itself rather than through
                # `_load()`; the check a given `doel` gets is the same one.
                _export_is_van(gekozen, current)
                if previous is None:
                    answer = _stamp(
                        Answer(
                            question="wat is er veranderd sinds de vorige scan",
                            findings=[
                                Finding(
                                    subject="vergelijking",
                                    outcome="er is niets om mee te vergelijken",
                                    certainty=Certainty.ESTABLISHED,
                                    evidence="er staat geen bewaarde vorige export naast deze export",
                                    reason="zet 'bewaren' in de configuratie om vorige exports te bewaren",
                                    subject_is_name=False,
                                )
                            ],
                            knowledge_age_days=knowledge.age_days,
                            knowledge_date=knowledge.date,
                        ),
                        current,
                    )
                    return _with_explanation(
                        render(
                            answer,
                            disclosure,
                            tool="rapport_wat_is_er_veranderd",
                            extra_names=names_from_export(current),
                            pseudonym_table_path=pseudonym_table_path,
                        ),
                        knowledge,
                        "rapport_wat_is_er_veranderd",
                    )
                old = load_export(previous)
                answer = _stamp(
                    compare_answer(old, current, knowledge, "run-diff"),
                    current,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="rapport_wat_is_er_veranderd",
                        extra_names=names_from_export(old) + names_from_export(current),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "rapport_wat_is_er_veranderd",
                )

            return _guarded(ctx, work, "rapport_wat_is_er_veranderd", {"doel": doel_clean})

    if "ha" in chapters:

        @server.tool()
        def ha_stand(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk ha. De HA-stand voor een wijziging: rolverdeling, sync en propagatie, geforceerde stand en het verschil tussen de running en de saved config, elk aan, uit of onbevestigd - en niet van toepassing op de twee standen die een paar beschrijven als er geen HA-paar is. Gebruik dit voordat je iets op de primary wijzigt. Het antwoord bewijst geen werkende failover en zegt niets over de configuratie van de partner."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    ha_state(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="ha_stand",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "ha_stand",
                )

            return _guarded(ctx, work, "ha_stand", {"doel": doel_clean})

    if "config" in chapters:

        @server.tool(description=CONFIG_DRIFT_DESCRIPTION)
        def config_drift(doel: str = "", *, ctx: Context) -> str:
            """Running against saved, from the export on disk (the public MCP
            description is the pinned module constant above).

            Always registered: it reads the export like every other reading
            tool and needs neither a scan configuration nor `onderhoud`. The
            configuration lines it may show are fenced in `config_drift.py`
            (openheid, secrets, shape, command heads); the disclosure seam
            below does the rest, exactly as for every other answer.

            `doel` goes through the same seam as on every export-backed
            reading tool (`_load_for`): an unknown one is refused with
            `ONBEKEND_DOEL_TEXT`, never echoed, and a configured one must be
            the target this export describes.
            """
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    drift_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="config_drift",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "config_drift",
                )

            return _guarded(ctx, work, "config_drift", {"doel": doel_clean})

    if "beveiliging" in chapters:

        @server.tool()
        def beveiliging_verstopte_regels(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk beveiliging. De negenentwintig verstopte regels waar geen alarm op staat: per regel of hij geraakt is, op welke objecten, en waarom dat niet opvalt. Gebruik dit als de vraag is wat er in deze configuratie verstopt zit. De regels lezen configuratievelden en bewijzen geen gedrag."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    hidden_rules_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="beveiliging_verstopte_regels",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "beveiliging_verstopte_regels",
                )

            return _guarded(ctx, work, "beveiliging_verstopte_regels", {"doel": doel_clean})

    if "beveiliging" in chapters:

        @server.tool()
        def beveiliging_tls_baseline(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk beveiliging. Een TLS-cijfer per virtuele server (A+ tot en met T) met de bepalende kenmerken, plus de verdeling over de appliance en de gebruikte regelsetversie. Protocol en ciphers komen van het gebonden SSL-profiel als er een is. Dit is een configuratieweging, geen live scan."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    tls_baseline(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="beveiliging_tls_baseline",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "beveiliging_tls_baseline",
                )

            return _guarded(ctx, work, "beveiliging_tls_baseline", {"doel": doel_clean})

        @server.tool()
        def beveiliging_beheervlak(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk beveiliging. Staat het beheer van deze appliance open: blootstelling op data-plane-adressen, cleartext transport, het default beheercertificaat op productieverkeer en de RBAC-hardening. Elk van de vier is PASS, FAIL of NIET BEOORDEELD. Een netwerk-ACL voor het beheeradres ziet dit antwoord niet."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    mgmt_plane(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="beveiliging_beheervlak",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "beveiliging_beheervlak",
                )

            return _guarded(ctx, work, "beveiliging_beheervlak", {"doel": doel_clean})

        @server.tool()
        def beveiliging_headers(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk beveiliging. Staan de zes HTTP-securityheaders er echt op: per header aanwezig en gebonden, wel gedefinieerd maar niet gebonden, afwezig of niet beoordeeld. Een action of policy zonder effectieve RESPONSE-binding telt niet. HSTS telt alleen via een FrontEnd-SSL-profiel met hsts=ENABLED; de vserverbinding is afzonderlijk bewijs."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    headers_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="beveiliging_headers",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "beveiliging_headers",
                )

            return _guarded(ctx, work, "beveiliging_headers", {"doel": doel_clean})

        @server.tool()
        def beveiliging_scorekaart(doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk beveiliging. De Level-1 scorekaart uit de export: per control PASS, FAIL of NIET BEOORDEELD, met ernst, zekerheid en toepasselijkheid. De kop is 'X van Y beoordeeld' - nooit een percentage en nooit een letter voor de appliance als geheel. Onderaan staat vast wat buiten het bereik van deze meting valt."""
            doel_clean = _normalize(doel)

            def work():
                export, knowledge = _load_for(doel_clean)
                answer = _stamp(
                    scorecard_answer(export, knowledge),
                    export,
                )
                return _with_explanation(
                    render(
                        answer,
                        disclosure,
                        tool="beveiliging_scorekaart",
                        extra_names=names_from_export(export),
                        pseudonym_table_path=pseudonym_table_path,
                    ),
                    knowledge,
                    "beveiliging_scorekaart",
                )

            return _guarded(ctx, work, "beveiliging_scorekaart", {"doel": doel_clean})

    def _from_script(text, *, extra_values: tuple[str, ...] = (), for_operator: bool = False) -> str:
        """THE one seam through which write-script output reaches an answer.

        Two things happen here, and nothing from the script may enter the
        text without both. First the same masking a failed SCAN report
        already gets (`_scrub_error_text`, collect.py): the known values of
        every configured target - address, credential-target name,
        fingerprint - are replaced, case-insensitively and longest-first.
        The write script runs against the same appliance as the collector,
        so its stderr names the same address, and on its failure path its
        stdout carries whole NITRO payloads.

        Second a line cap. Masking bounds WHAT may travel, not HOW MUCH:
        forty lines of payload are an unread block of appliance data in the
        model's context even when every known value in them is masked. The
        text says how many lines were dropped, so the reader knows the block
        is a tail and not the whole story.

        The same boundary as `_short_report` in collect.py applies and is
        stated in docs/klant/SECURITY.md: this masks the values this product
        KNOWS as belonging to the target, not everything a script can print.

        SECURITY 13. `targets` is EMPTY in a configuration that carries
        `handelen` without `doelen` - the demo shape - and the masking then
        masked nothing while the documentation promised it did. `extra_values`
        closes that: the caller passes the values it knows from the ACTION
        context (the [TARGET] label the write script reports, and its
        identifying parts - `_context_values_to_mask` derives them and says
        which parts it deliberately leaves out), and those are masked in the
        bulk output too.

        Deliberately NOT applied to the lines that render the target itself:
        a human has to see what he is confirming. The caller decides per
        line, and the two tests in tests/test_handelen_zonder_code.py pin
        both halves.

        Measured (17-9-2026): the masking above only
        ever catches values this product ALREADY KNOWS belong to the target.
        Free script text can name an appliance object it does not know -
        not the configured target, not one of the call's own allowlisted
        arguments - a binding the script discovers mid-run, for instance.
        `disclosure._limit()` cannot pseudonymize a name it never collected
        either, so that name used to travel through this seam unmasked, at
        'beperkt' exactly as at 'volledig'. Below 'volledig' this seam now
        suppresses non-empty free script text outright instead of trying to
        catch every name that might appear in it - the ONE route every
        write-script text takes (preview, failed write output, the action-id
        a script reports), so the suppression cannot be bypassed by calling
        some OTHER seam instead. Empty text stays empty: an ABSENT plan or
        status is silence, not a statement, and the callers above already
        treat that silence as its own case (e.g. "het schrijfscript meldde
        niet wat het zou doen").

        `for_operator=True` is the one, narrow exception: the operator's own
        channel (the confirmation window/SSO/file the code is presented
        through) needs the real, free-text target so a human can see what he
        is confirming - `_present()`'s two call sites are the only callers
        that pass it. Every other caller, including this function's OWN
        default, stays suppressed below 'volledig'; the model never reads
        `for_operator=True` output. `_script_notes()` recognises the exact
        suppression text below and gives it its own honest evidence instead
        of a caller's claim that it is quoted from the script - that claim
        stopped being true the moment this function replaced the text.
        """
        if not str(text).strip():
            return ""
        if disclosure is not Disclosure.FULL and not for_operator:
            return _SUPPRESSED_SCRIPT_TEXT
        scrubbed = str(text)
        for target in targets.values():
            scrubbed = _scrub_error_text(scrubbed, target)
        for value in sorted(
            {str(v).strip() for v in extra_values if v and str(v).strip()},
            key=len,
            reverse=True,
        ):
            # Longest first, for the same reason as _scrub_error_text: two
            # known values may overlap, and replacing the shorter one first
            # leaves the rest of the longer one standing.
            scrubbed = re.sub(re.escape(value), "<doel>", scrubbed, flags=re.IGNORECASE)
        lines = scrubbed.splitlines()
        if len(lines) > _SCRIPT_LINE_CAP:
            dropped = len(lines) - _SCRIPT_LINE_CAP
            lines = lines[:_SCRIPT_LINE_CAP] + [f"... ({dropped} regels ingekort)"]
        return "\n".join(lines)

    def _report_burn(count: int) -> None:
        send_notice(code_presenter, BURN_NOTICE)

    confirmations = ConfirmationStore(on_burn=_report_burn)

    def _with_marker(text: str, marker: str) -> str:
        """The proposal's own letter, appended AFTER rendering.

        Deliberately not a Finding in the proposal's Answer: `_minimal()`
        counts findings and drops the findings themselves, so at
        `openheid: minimaal` a marker that was a finding would silently
        disappear - and the whole point of the letter is that it is there
        when two proposals are open. It needs no masking either: it carries
        no object name, no target and no tool name, which is the same
        reason `status_ververs` sits outside the seam.

        The SAME `marker_line()` the channel uses (code_channel._message()),
        so the letter the operator reads and the letter the model reads
        cannot drift apart.

        Worth naming so nobody assumes otherwise: every other text on this writing path ends in the two
        closing stamps `_stamped()` puts on it ("Kennisbasis van ..." /
        "Gegevens van ...", `Answer.to_text()`'s own last two lines) because
        nothing runs after `_rendered()` for them. This text is the one
        exception - the marker line is appended AFTER those stamps, so a
        proposal answer's last line is the letter, not a stamp. Nothing
        reads "the last line" of an answer as a stamp today, so nothing
        breaks; it is written down here so a future reader does not trust
        that of this one text.
        """
        return f"{text}\n{marker_line(marker)}"

    # How the proposal NAMES the channel, taken from the channel itself so
    # the text cannot promise a window while a file was configured. The
    # fallback is vague rather than wrong: a caller-supplied presenter that
    # names no channel gets no invented one.
    _channel_label = getattr(code_presenter, "label", None) or "kanaal van de beheerder"
    # "handeling-", niet een productnaam: een bundelnaam beschrijft wat erin zit.
    bundle_name = "handeling-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")

    # THE SINGLE-WRITER GATE. `_act()` hands the
    # write script to `asyncio.to_thread`, so without this two confirmed
    # actions really did run at the same time (measured: two identical
    # 1-second run windows in tests/test_handelen_zonder_code.py). The write
    # script keeps its ownership and rollback bookkeeping in ONE shared file
    # it reads, modifies and writes back; two writers in that file lose each
    # other's administration.
    #
    # Keyed by EVENT LOOP, not one bare `asyncio.Lock()` here: a lock binds
    # to the first loop that uses it and refuses every other one, while
    # `build_server()` runs outside a loop and a caller may serve this same
    # server object from more than one loop over its life. A served product
    # runs exactly one loop, so this is one lock per server process - which
    # is exactly the scope this gate claims and no more. BETWEEN PROCESSES it
    # guarantees nothing: two servers on one appliance are the write script's
    # own problem, and it holds its own exclusive lock on its register. Said
    # plainly in docs/klant/SECURITY.md rather than left to be assumed.
    writer_locks: weakref.WeakKeyDictionary[object, asyncio.Lock] = weakref.WeakKeyDictionary()

    @asynccontextmanager
    async def _writer_gate(worker_slot: list):
        """The gate follows the WORKER, not the task that waits for it.

        `worker_slot` is empty until `work()` has handed the real run to a
        worker thread; from then on it carries that run's future. Why the
        difference matters (MEASURED):
        a client may cancel an in-flight confirmed call
        (`notifications/cancelled` - a timeout, an operator pressing stop),
        which cancels only the coroutine awaiting the result. The write
        script itself is already in its thread and cannot be called back, so
        releasing the lock while that thread runs let a second confirmed
        action into the register mid-write (measured: two real runs
        overlapping by 3.4 s). The lock is therefore released from a
        done-callback on the run's own future once a run is under way, and
        only from here (immediately) when there is none: the preview, the
        redeem, a refusal.
        """
        loop = asyncio.get_running_loop()
        lock = writer_locks.get(loop)
        if lock is None:
            lock = asyncio.Lock()
            writer_locks[loop] = lock
        try:
            # WAITING, not refusing: a second operator whose action arrives
            # while the first is running is not doing anything wrong, and a
            # refusal would cost them their code for nothing. asyncio.Lock is
            # FIFO, so the order is the order of arrival.
            await asyncio.wait_for(lock.acquire(), timeout=WRITER_GATE_WAIT_S)
        except TimeoutError:
            raise ToolError(WRITER_BUSY) from None
        try:
            yield
        finally:
            worker = worker_slot[0] if worker_slot else None
            if worker is not None and not worker.done():
                # Exactly one release either way: a future completes once, so
                # the callback fires once - and the `done()` branch above can
                # only be taken when no callback was scheduled.
                worker.add_done_callback(lambda _finished: lock.release())
            else:
                lock.release()

    def _stamped(answer: Answer) -> Answer:
        """The two closing stamps of an answer, on the WRITING path too.

        The same two lines a reading answer carries, out of the same two
        sources: the knowledge fields an analysis module fills in when it
        builds its answer (`knowledge.date` / `knowledge.age_days`), and
        `stamp_data()` at the server boundary. A writing answer is built
        here instead of in an analysis module, so both happen here - not a
        second mechanism, the same two.

        Fail-open on the load, exactly as `_write_names()` is: a writing tool
        must keep working without a readable export, and an unstamped answer
        then says "ONBEKEND" itself instead of guessing. That sentence is
        honest when the package really is missing; what it must not do is
        report the ABSENCE OF A STAMP as an absent knowledge base - which is
        what every writing answer did before this.
        """
        try:
            export, knowledge = _load()
        except Exception:  # noqa: BLE001 - a writing tool must not need a readable export
            return answer
        return _stamp(
            replace(
                answer,
                knowledge_age_days=knowledge.age_days,
                knowledge_date=knowledge.date,
            ),
            export,
        )

    def _tool_is_registered(name: str) -> bool:
        """Whether THIS server really registered a tool by that name.

        Asked of the server itself, so the answer follows the BUILD instead
        of a hand-kept list the next task would have to remember to update.
        Fail-closed on anything unexpected: an unknown answer counts as "not
        registered", which only ever makes a message say MORE (where else to
        look), never less.
        """
        manager = getattr(server, "_tool_manager", None)
        registered = getattr(manager, "_tools", None)
        return name in registered if isinstance(registered, dict) else False

    def _stand_hint() -> str:
        """The tail every "vraag de stand op met onderhoud_upgrade_stand"
        sentence carries when that tool is NOT on this server.

        `onderhoud_upgrade_stand` used to be
        introduced by a later task and exist nowhere on this branch, so
        those refusals sent the operator to a tool that could not answer.
        The sentence keeps naming it - it IS the tool that answers, and the
        wording is product surface - and said where the stand really was
        until it landed.

        `onderhoud_upgrade_stand` landed later
        (this docstring used to still claim otherwise). Both call sites sit
        behind `onderhoud_upgrade_fase`'s own registration gate, which
        requires `onderhoud is not None` - a strict SUBSET of what
        `onderhoud_upgrade_stand` itself requires (`"onderhoud" in
        chapters and onderhoud is not None`, no allowlist/`writing_allowed`
        gate at all) - so on every server where `_stand_hint()` can run
        today, `onderhoud_upgrade_stand` is provably already registered and
        this function returns `""`. The `_tool_is_registered()` check
        (a BUILD question, not a hand-kept list) stays as defense in depth
        against the two gates drifting apart again, not because the branch
        is expected to fire."""
        if _tool_is_registered("onderhoud_upgrade_stand"):
            return ""
        return (
            " Dat gereedschap is op deze server nog niet aangemeld; tot dat zo is staat de "
            "stand in het ledger zelf, in de map die onderhoud.ledgermap aanwijst."
        )

    def _open_phase_refusal(open_phase) -> str:
        """The cross-tool refusal, with the two things it never said: WHICH
        phase holds the target, and WHEN this refusal lifts on its own."""
        if open_phase.started is None:
            when_it_lifts = (
                f"fase {open_phase.phase} staat open zonder leesbare starttijd, dus de "
                f"tijdslimiet van {open_phase.limit_s} s is er niet tegen af te meten; deze "
                "weigering blijft staan tot er een sluitregel in het ledger staat"
            )
        else:
            lifts_at = open_phase.started + timedelta(seconds=open_phase.limit_s)
            when_it_lifts = (
                f"fase {open_phase.phase} is gestart op "
                f"{open_phase.started.strftime('%Y-%m-%dT%H:%M:%SZ')}; komt er geen sluitregel, "
                "dan vervalt deze weigering vanzelf na de tijdslimiet van "
                f"{open_phase.limit_s} s, om {lifts_at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
        return (
            "er staat nog een fase open op dit doel; vraag de stand op met "
            f"onderhoud_upgrade_stand.{_stand_hint()} ({when_it_lifts})"
        )

    def _open_phase_evidence(open_phase) -> str:
        """The ledger fact behind the refusal above. `phase` is bounded by
        `OpenPhase` itself; the run is left out on purpose - `OpenPhase.run`
        is an unbounded ledger string this refusal never echoes."""
        if open_phase.started is None:
            return OPEN_FASE_ZONDER_TIJD_EVIDENCE.format(fase=open_phase.phase)
        return OPEN_FASE_EVIDENCE.format(
            fase=open_phase.phase, gestart=open_phase.started.strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    def _lift_findings(expired) -> list[Finding]:
        """What the operator is told when the refusal above is GONE.

        A refusal that disappears without a word is indistinguishable from a
        refusal that was never there, and those two are not the same thing:
        one of them means a phase started on this target and never wrote a
        closing line. So the tool that IS let through says so in its own
        answer, in this product's own vocabulary - `mislukt`, reden
        `tijdslimiet`, the words `evaluate_phase()` writes for exactly this.
        """
        return [
            Finding(
                subject="vorige fase",
                outcome=(
                    f"fase {f.phase} staat in het ledger op gestart zonder sluitregel en is "
                    f"over zijn tijdslimiet van {f.limit_s} s heen; die fase telt daarmee als "
                    "mislukt met reden tijdslimiet, en houdt dit doel niet langer bezet"
                ),
                certainty=Certainty.ESTABLISHED,
                evidence=(
                    "een regel fase_gestart in het ledger zonder sluitregel, ouder dan de tijdslimiet van die fase"
                ),
                subject_is_name=False,
            )
            for f in expired
        ]

    # THE REGISTER OF UNDECIDED STARTS - one per server process, the same
    # scope the single-writer gate below claims and no more. A start whose
    # runner was launched but whose `fase_gestart` row this server did not
    # see holds its target here until that row lands (then the ledger's own
    # open-phase gate takes over) or the phase's time limit passes (then it
    # lifts, audibly). Measured before it existed: a slow runner left an
    # empty ledger behind the "telt niet als gestart" answer, and a new
    # proposal plus confirmation for the same phase and run started a SECOND
    # runner against the same appliance. After a restart of the server only
    # the ledger decides again - said so in docs/klant/SECURITY.md.
    undecided_starts = UndecidedStarts()

    def _moment(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _undecided_how(entry: UndecidedStart) -> str:
        if entry.waiting_until is not None:
            return ONBESLIST_WACHT_TEXT.format(tot=_moment(entry.waiting_until))
        if entry.broke_off:
            return ONBESLIST_AFGEBROKEN_TEXT
        return ONBESLIST_GEWACHT_TEXT.format(wacht=entry.wait_s)

    def _undecided_evidence(entry: UndecidedStart) -> str:
        if entry.waiting_until is not None:
            wat = ONBESLIST_WACHT_EVIDENCE.format(tot=_moment(entry.waiting_until))
        elif entry.broke_off:
            wat = ONBESLIST_AFGEBROKEN_EVIDENCE
        else:
            wat = ONBESLIST_GEWACHT_EVIDENCE.format(wacht=entry.wait_s)
        return ONBESLISTE_START_EVIDENCE.format(
            gestart=_moment(entry.launched),
            wat=wat,
            deadline=_moment(entry.deadline),
        )

    def _undecided_refusal(entry: UndecidedStart) -> str:
        return ONBESLISTE_START_TEXT.format(
            fase=entry.phase,
            run=entry.run,
            hoe=_undecided_how(entry),
            limiet=entry.limit_s,
            deadline=_moment(entry.deadline),
        )

    def _undecided_stand_finding(entry: UndecidedStart) -> Finding:
        return Finding(
            subject="onbesliste start",
            outcome=ONBESLISTE_START_STAND_TEXT.format(
                fase=entry.phase,
                run=entry.run,
                hoe=_undecided_how(entry),
                limiet=entry.limit_s,
                deadline=_moment(entry.deadline),
            ),
            certainty=Certainty.ESTABLISHED,
            evidence=_undecided_evidence(entry),
            subject_is_name=False,
        )

    def _undecided_lapse_finding(entry: UndecidedStart) -> Finding:
        """The register's counterpart of `_lift_findings()`: a hold that
        lifts at the time limit says so, never disappears without a word."""
        return Finding(
            subject="onbesliste start",
            outcome=ONBESLISTE_START_VERVALLEN_TEXT.format(fase=entry.phase, run=entry.run, limiet=entry.limit_s),
            certainty=Certainty.ESTABLISHED,
            evidence=ONBESLISTE_START_VERVALLEN_EVIDENCE.format(
                gestart=_moment(entry.launched),
                deadline=_moment(entry.deadline),
            ),
            subject_is_name=False,
        )

    def _write_names(doelnaam: str) -> tuple[str, ...]:
        """Which names the seam must mask on the writing path.

        The ALLOWLIST is the source, not the export: every object a writing
        tool can name is in there by construction, and the writing path must
        keep working when there is no readable export. The export names are
        added when they are available, because a script's own output may name
        an object the allowlist does not.

        MEASURED: the object form of an
        allowlist entry wants a TUPLE of values (`{"certnaam": ("...",)}`).
        `namen.update(values)` used to run on whatever a field carried, with
        no type check - a configuration mistake that writes a bare STRING
        there explodes into its individual CHARACTERS on `set.update()`. That
        is not only a masking-precision bug: it once handed
        `disclosure._next_free_pseudonym()` a real name set containing single
        letters like "o", "b" or "t" - every `object-NN` candidate contains
        at least one of them, so that generator could no longer find a free
        pseudonym at all and looped FOREVER (measured with a faulthandler
        stack dump: `_next_free_pseudonym` never returned). A quietly
        narrower mask set is a leak path at `openheid: beperkt`; this is
        worse - a hang. Only a proper COLLECTION of strings may widen the
        mask set by exploding into its members here; a bare string (the
        exact configuration mistake this paragraph measures) is instead
        added as ONE name - not skipped (skipping it masked LESS than it
        safely could) and not exploded into
        characters (that is the hang this paragraph exists to prevent).
        Anything that is neither a proper collection nor a string is
        skipped rather than guessed at.

        CORRECTION: the paragraph above closes
        exactly the ONE calling path that could hand `_next_free_pseudonym()`
        a MALFORMED (wrongly typed) allowlist value - it does not, and
        structurally cannot, close the generator's loop itself. A perfectly
        well-typed one-character name reaches the same generator just as
        easily - `names_from_export()` on an ordinary one-character
        appliance object name, or a correctly typed `extra_names=("o",)` -
        and hangs it exactly the same way, with no allowlist and no type
        error involved anywhere. `disclosure._next_free_pseudonym()` is now
        bounded THERE, at the one place this search happens
        (`_MAX_PSEUDONYM_ATTEMPTS`, `PseudonymSpaceExhausted`): a fail-closed
        raised error after a fixed number of attempts, never a hang,
        regardless of which caller or which path handed it the colliding
        name. This function's type check remains worth keeping (it still
        closes the CHARACTER-EXPLOSION masking-precision bug, independently
        of the hang), but it is not - and was never - the fix for the loop.
        """
        namen = set()
        for entry in allowlist.per_target.get(doelnaam, {}).values():
            if isinstance(entry, dict):
                for values in entry.values():
                    if isinstance(values, (list, tuple, set, frozenset)):
                        namen.update(v for v in values if isinstance(v, str))
                    elif isinstance(values, str):
                        # The same
                        # configuration mistake the type check above guards
                        # against (a bare STRING where the object form wants
                        # a tuple) used to be SKIPPED here entirely - masking
                        # LESS than it safely could. A bare string is one
                        # name, not a collection to explode (`set.update()`
                        # on a string IS the character-explosion hang
                        # this function must never reopen - see the
                        # docstring above), so it is added as ONE name
                        # instead. Fail-safe direction: in doubt, widen the
                        # mask set, never narrow it.
                        namen.add(values)
        try:
            export, _knowledge = _load()
        except Exception as exc:  # noqa: BLE001 - a writing tool must not need a readable export
            print(
                f"[maskering] {doelnaam}: export niet leesbaar ({type(exc).__name__});"
                " de maskering op de schrijfweg valt terug op de allowlist alleen",
                file=sys.stderr,
                flush=True,
            )
            return tuple(sorted(namen))
        namen.update(names_from_export(export))
        return tuple(sorted(namen))

    def _firmware_bundle_or_reason():
        """The one bundle in `onderhoud.firmwaremap` (`FirmwareBundle`), the
        honest reason there is none (`str`), or `None` without `onderhoud` -
        the same `firmware_target_build()` that gives the runner its
        `-Doelbuild`."""
        if onderhoud is None:
            return None
        try:
            return firmware_target_build(onderhoud.firmwaremap)
        except ActionError as exc:
            return _firmware_reason(exc)

    def _firmware_reason(exc: ActionError) -> str:
        """The reason an `ActionError` gives, for an answer at THIS
        disclosure level: zero or more than one bundle names the local
        firmware directory (or the bundles in it) only at 'volledig'; below
        that the sentence says what the configured directory holds."""
        if isinstance(exc, FirmwareBundleError) and disclosure is not Disclosure.FULL:
            return exc.zonder_pad
        return str(exc)

    def _upgrade_floor(doelnaam: str) -> tuple[Floor, CurrentBuild, object | None]:
        """The security floor of the appliance in the export, from the
        knowledge package - `export_floor()` over the same `_load()` every
        reading tool uses, read afresh at the proposal AND at the execution
        - together with the current build from that same export
        (`export_current_build()`, `config/nsversion`: R0 closes a target
        build in another release line) and that knowledge package (the
        proposal names the bulletins that stay open below the floor). A
        proposal must not need a readable export: anything that fails here is
        a floor and a current build that are not there, with their reason,
        and R0's floor gate then closes on them rather than this call
        failing.

        A READABLE export must describe `doelnaam` (the canonical target of
        this call): there is one export per server, and the build of another
        appliance would open R0's floor gate for this one - and stand in
        every proposal as this target's build. An export of another target,
        or one that records none, is refused (`_export_is_van`, a
        `ToolError`), deliberately OUTSIDE the fallback above: that fallback
        would turn the refusal into "not readable" and let an acceptance
        through."""

        def niet_leesbaar(exc: Exception) -> tuple[Floor, CurrentBuild, None]:
            reden = f"de export of het kennispakket is niet leesbaar ({type(exc).__name__})"
            return Floor(None, "", "de export en het kennispakket", reden), CurrentBuild(None, "de export", reden), None

        try:
            export, knowledge = _load()
        except Exception as exc:  # noqa: BLE001 - a writing tool must not need a readable export
            return niet_leesbaar(exc)
        _export_is_van(doelnaam, export)
        try:
            return export_floor(export, knowledge), export_current_build(export), knowledge
        except Exception as exc:  # noqa: BLE001 - a writing tool must not need a readable export
            return niet_leesbaar(exc)

    def _export_drift_finding(doelnaam: str) -> Finding:
        """What the export says about drift between running and saved -
        COUNTS, never a configuration line - for the proposals of
        `config_opslaan` and of R1.

        Fail-open on the export, exactly as `_write_names()` and
        `_stamped()` are: a writing tool must keep working without a
        readable export, and the drift line then says so instead of guessing.

        Counts are this target's only when the export describes `doelnaam`
        (`_export_is_van`, the comparison the upgrade phases and the reading
        tools make): from an export of another target, or one that records
        none, the line is "niet vastgesteld" with that refusal as its reason.
        """
        niet_vastgesteld = Finding(
            subject="drift",
            outcome="volgens de export niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="de running- en saved-configuratie in de export",
            reason="de export draagt geen leesbare running- en saved-configuratie of geen leesbaar tijdstempel",
            subject_is_name=False,
        )
        try:
            export, _knowledge = _load()
            dimension, _gaps = _drift_dimension(export)
            moment = datetime.fromisoformat(str(export.collected_at))
        except Exception:  # noqa: BLE001 - a proposal must not need a readable export
            return niet_vastgesteld
        tellingen = re.search(r"([0-9]+) alleen in running, ([0-9]+) alleen in saved", dimension.evidence)
        if tellingen is None:
            return niet_vastgesteld
        try:
            _export_is_van(doelnaam, export)
        except ToolError as exc:
            return Finding(
                subject="drift",
                outcome="niet vastgesteld",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=VERVANGEN_DOEL_EVIDENCE,
                reason=str(exc),
                subject_is_name=False,
            )
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        datum = moment.astimezone(UTC).date().isoformat()
        tellingen_tekst = (
            f"volgens de export van {datum}: {tellingen.group(1)} alleen in running, "
            f"{tellingen.group(2)} alleen in saved (zie config_drift)"
        )
        evidence = "de running- tegenover de saved-configuratie in de export; tellingen, nooit een regel"
        if dimension.state == UNCONFIRMED:
            # The same state `config_drift` and `ha_stand` give: the counts
            # were made, but lines whose value the collector withheld could
            # carry the change the headers report. Two zeros here are not
            # "no drift", and the proposal may not present them as such.
            return Finding(
                subject="drift",
                outcome=f"{tellingen_tekst}, maar {DRIFT_LABEL} is {UNCONFIRMED}",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=evidence,
                reason=dimension.reason,
                subject_is_name=False,
            )
        return Finding(
            subject="drift",
            outcome=tellingen_tekst,
            certainty=Certainty.ESTABLISHED,
            evidence=evidence,
            subject_is_name=False,
        )

    def _config_opslaan_voorstel_findings(doelnaam: str) -> list[Finding]:
        """The two findings `config_opslaan`'s proposal adds of its own,
        after the fixed lines: the export drift, and that the role is
        decided live, at the execution, not now."""
        rol = Finding(
            subject="rol",
            outcome=CONFIG_OPSLAAN_ROL_TEXT,
            certainty=Certainty.ESTABLISHED,
            evidence="de rolcontrole (show ha node) loopt in het opslagscript, vlak voor save ns config",
            subject_is_name=False,
        )
        return [_export_drift_finding(doelnaam), rol]

    def _vervangen_voorstel_findings(dienst: str, doelnaam: str) -> tuple[list[Finding], tuple[str, ...]]:
        """The proposal of `certificaat_vervangen`: the certificate on
        `dienst` now, and every use of it outside that one binding
        (`action.replacement_findings`, the reader of
        `certificaat_wat_breekt_er`) - plus the names of THAT reading of the
        export, so the proposal is masked with the same export it was read
        from and not with a second read a scan could have swapped in between.

        Only about the target of this action. There is ONE export per server,
        so it may describe another appliance: the same comparison a reading
        tool with a `doel` makes (`_export_is_van`), and on a mismatch - or an
        export that records no target - the line is "niet vastgesteld", never
        a use (or a silence) about the certificate of another appliance.

        Nor about a binding this server itself changed since the scan: after
        a write the export still names the certificate that was replaced.

        Fail-open on the export like `_export_drift_finding()`: a writing
        tool must keep working without a readable export, and the line then
        says the use is not established."""

        def niet_vastgesteld(evidence: str, reason: str) -> list[Finding]:
            return [
                Finding(
                    subject=REPLACED_CERTIFICATE_SUBJECT,
                    outcome=USE_NOT_ESTABLISHED_OUTCOME,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=evidence,
                    reason=reason,
                    subject_is_name=False,
                )
            ]

        try:
            export, knowledge = _load()
        except Exception as exc:  # noqa: BLE001 - a proposal must not need a readable export
            return niet_vastgesteld("de export", f"de export is niet leesbaar ({type(exc).__name__})"), ()
        if export.target_name is None or export.target_name_refused:
            return niet_vastgesteld(VERVANGEN_DOEL_EVIDENCE, EXPORT_DOEL_ONBEKEND_TEXT), ()
        if export.target_name != doelnaam:
            return niet_vastgesteld(VERVANGEN_DOEL_EVIDENCE, ander_doel_text(export.target_name, disclosure)), ()
        if collected_for(provenance_dir, doelnaam, export.manifest_hash, export_dir) is None:
            return niet_vastgesteld(VERVANGEN_DOEL_EVIDENCE, HERKOMST_NIET_VASTGESTELD_TEXT), ()
        freshness = writes_since_scan.sentence()
        if freshness:
            return niet_vastgesteld(VERVANGEN_VERSHEID_EVIDENCE, freshness), ()
        try:
            return replacement_findings(export, knowledge, dienst), names_from_export(export)
        except Exception as exc:  # noqa: BLE001 - a proposal must not need a readable export
            return niet_vastgesteld("de export", f"de export is niet leesbaar ({type(exc).__name__})"), ()

    def _r1_drift_voorstel_findings(doelnaam: str) -> list[Finding]:
        """R1's proposal: the export drift and the three ways its drift gate
        opens, so the operator chooses BEFORE the window instead of reading a
        closed gate afterwards."""
        keuze = Finding(
            subject="driftpoort",
            outcome=R1_DRIFT_KEUZES_TEXT,
            certainty=Certainty.ESTABLISHED,
            evidence="de driftpoort van R1, gemeten in de eigen sessie van de fase",
            subject_is_name=False,
        )
        return [_export_drift_finding(doelnaam), keuze]

    async def _act(ctx: Context, tool: str, raw_arguments: dict, bevestiging: str) -> str:
        """THE one path for all seven writing tools. Elke aanroep begint met
        een preview (het script draait met -WatIs en wijzigt niets); daaruit
        komt het doel-etiket dat het schrijfscript zelf meldt via [TARGET] -
        de bevestigingscode wordt aan DIT etiket gebonden, niet aan de
        geconfigureerde scanlijst. Zonder code: dat voorstel plus een verse
        code. Met code: dezelfde preview om het actuele doel opnieuw vast te
        stellen, dan inwisselen (altijd verbruikt, ook bij mislukking), dan
        de echte run en het teruglezen.

        `validate()` staat BINNEN `work()`, dus achter `_decide()`: een
        client die uberhaupt niets mag, of een sessie die zich onderweg
        omkatte, hoort ook geen weigering over deze aanroep te krijgen -
        die weigering bevestigt immers dat dit gereedschap hier bestaat en
        wat het van de aanroeper aannam. (Sinds een latere fix noemt zij de allowlist
        zelf niet meer; de volgorde blijft hetzelfde en om dezelfde reden.)
        De permissiebeslissing krijgt de gestripte RUWE argumenten
        (dezelfde canonieke vorm die `_normalize()` de leestools geeft, en
        onder 'beperkt' dus de pseudoniemen zoals de aanroeper ze typte)
        plus `bevestiging` als JA/NEE - nooit de code zelf: die is een
        geheim tussen voorstel en operator, geen invoer voor beleid. De
        handeling zelf werkt op de vertaalde echte naam. Dat wijkt onder
        'beperkt' af van de regel in de moduledocstring van `permissions`
        (beslissing en handeling zien dezelfde waarde): onder `allow_all`
        beslist er niets, maar een beslispunt dat meer doet moet de
        vertaalde naam beoordelen, niet het pseudoniem.

        ASYNC, om dezelfde reden als `status_ververs`: het schrijfscript
        mag tot vijf minuten draaien (`handelen._TIMEOUT_S`), en een
        synchrone toolfunctie blokkeert de event loop van de server die
        hele tijd - geen andere aanroep, geen ping, geen annulering komt
        er dan doorheen. `perform()` loopt daarom via
        `asyncio.to_thread(...)`, en deze weg gaat door
        `_guarded_async()` in plaats van `_guarded()`."""
        stripped = {name: str(value).strip() for name, value in raw_arguments.items()}
        # `doel` names the allowlist SECTION; it is not an argument of the
        # write script. Read once here, and hand validate() a dict without it.
        # `stripped` itself stays WHOLE on purpose: the permission decision at
        # the bottom of _act() snapshots it, and it must keep seeing the call
        # exactly as the caller made it. Resolving the name to a section stays
        # inside work(), behind _decide(), for the same reason validate() does:
        # its refusal talks about the configuration.
        given_target = stripped.get("doel", "")
        action_arguments = {name: value for name, value in stripped.items() if name != "doel"}

        def _rendered(doelnaam: str, answer, caller_name: str | None, extra_names: tuple[str, ...] = ()) -> str:
            """THE one exit of the writing path. Everything a writing tool
            says to the model goes through here, so `openheid` governs the
            writing half exactly as it governs the reading half.

            It is also where a LIFTED cross-tool refusal gets its word in.
            The notice is a `Finding` like any
            other, APPENDED - never prepended, so every answer this product
            pins byte-for-byte keeps its opening lines - and it therefore
            passes the same seam, the same masking and the same stamps as
            the answer it travels with, instead of being glued on as bare
            text afterwards.
            """
            if lift_notices and isinstance(answer, Answer):
                answer = replace(answer, findings=[*answer.findings, *lift_notices])
            # `extra_names`: the names of an export reading an answer was
            # BUILT from, on top of the fresh reading `_write_names()` makes -
            # a scan between the two must not leave a name of the older one
            # unmasked.
            return render(
                _stamped(answer),
                disclosure,
                tool=tool,
                extra_names=_write_names(doelnaam) + _via_pseudoniem(given_target, doelnaam) + tuple(extra_names),
                caller_name=caller_name,
                pseudonym_table_path=pseudonym_table_path,
            )

        def _note(
            subject: str,
            outcome: str,
            evidence: str,
            *,
            certainty: Certainty = Certainty.ESTABLISHED,
            reason: str = "",
        ) -> Finding:
            """A finding of a FAILED outcome of this path.

            `subject_is_name=False` for the reason the proposal below states
            at length: every subject here is this product's own vocabulary
            (the tool, an argument name, "doel"), never an appliance object.
            The object names sit in the OUTCOMES, and those the seam masks.

            `ESTABLISHED` by DEFAULT because that is what most of these
            findings are: the script said this and this layer read it - what
            failed is the OUTCOME, not the reading of it. There is one branch
            where that reasoning does not hold, and it therefore passes
            `Certainty.NOT_ESTABLISHED` with a reason: the run that threw
            instead of reporting. Nothing was read there at all, and the
            write outcome is precisely the verdict-carrying field - so
            `[vastgesteld]` under a sentence that says the outcome is NOT
            established would be the silent green this product does not do.
            `Finding` itself refuses a non-established statement without a
            reason (answer.py), so the reader always gets both.
            """
            return Finding(
                subject=subject,
                outcome=outcome,
                certainty=certainty,
                evidence=evidence,
                reason=reason,
                subject_is_name=False,
            )

        def _script_notes(subject: str, text: str, evidence: str) -> list[Finding]:
            """Script-authored text as one finding PER LINE, never as one blob.

            `Answer.to_text()` writes a finding as
            `- <subject>: <outcome> [<certainty>]`. Put a MULTI-LINE string in
            one of its fields and the second and further lines land in the
            findings block WITHOUT that prefix, while this product's certainty
            marker ends up glued to the last line the SCRIPT wrote. A write
            script - which runs against the appliance and prints what the
            appliance says - can then author a line that reads as a finding of
            this product and a line that reads as this product's verdict. That
            is the forging class `answer.repeatable_token` exists for, and the
            one measured elsewhere in this product as "a forged
            `[vastgesteld]` line via a newline in a status".

            No second mechanism is invented for it: the way this product says
            SEVERAL things is the findings LIST, so every line the script
            printed becomes a finding of its own - its own subject prefix, its
            own evidence, its own marker. A forged line can then only ever sit
            INSIDE an outcome, behind a subject this layer wrote.

            `_from_script()` still runs first and keeps doing what it does
            (masking plus the line cap); this bounds the SHAPE, not the
            amount. Blank lines are dropped and an entirely empty output says
            so, because a subject with an empty statement is not a statement.

            ONE line is never the script's own, even though it arrives
            embedded in the same text: `_from_script()`'s own truncation
            note. It gets its own, honest evidence
            (`_TRUNCATION_NOTE_EVIDENCE`) instead of the caller's claim of
            script provenance.

            A SECOND line is the same kind of impostor, for the same reason:
            `_from_script()`'s
            own suppression text, returned in place of the script's real
            output below 'volledig'. The caller's `evidence` claims this
            line is quoted from the script - true when `_from_script()`
            actually relayed it, false the moment it replaced it instead.
            `_SUPPRESSED_SCRIPT_EVIDENCE` says so honestly.
            """
            regels = [regel for regel in text.splitlines() if regel.strip()]
            if not regels:
                return [
                    _note(
                        subject,
                        "het schrijfscript drukte niets af",
                        "de uitvoer van het schrijfscript was leeg",
                    )
                ]

            def _evidence(regel: str) -> str:
                if _TRUNCATION_NOTE.match(regel):
                    return _TRUNCATION_NOTE_EVIDENCE
                if regel == _SUPPRESSED_SCRIPT_TEXT:
                    return _SUPPRESSED_SCRIPT_EVIDENCE
                return evidence

            return [_note(subject, regel, _evidence(regel)) for regel in regels]

        def _failure(doelnaam: str, question: str, *findings: Finding) -> ToolError:
            """A FAILED outcome, through the SAME exit as a successful one.

            The SEMANTICS do not move: this stays a `ToolError`, so the call
            is `isError=True` and no model can read a failure as an answer.
            Only the TEXT moves. `_from_script()` masks what this product
            KNOWS about a configured target - address, credential-target
            name, fingerprint - and says so itself; an appliance OBJECT name
            that a failing script prints travels straight through it. That
            was harmless while the writing tools existed only at 'volledig',
            and it is a real leak now that they also exist at 'beperkt': a
            failing run is the branch that prints the most. `_from_script()`
            still runs FIRST, before this seam - belt and braces, and its
            line cap has no equivalent here.
            """
            return ToolError(
                _rendered(
                    doelnaam,
                    Answer(question=question, findings=list(findings)),
                    caller_name=None,
                )
            )

        def _undecided_gate(doelnaam: str, question: str, now: datetime, rows) -> None:
            """The register of undecided starts, asked FIRST at the place
            every writing tool asks `blocking_phase()` - the phase tool's
            proposal and confirmed call, and the gate of the other writing
            tools - with the SAME strictly read `rows` that gate judges, so a
            row that lands in between cannot drop the hold while the
            open-phase gate still reads an older, empty ledger. A hold
            refuses through `_failure()` - the same seam as every other
            failed outcome, never a bare string; a hold that lapsed at the
            time limit joins `lift_notices`, so the answer that IS let
            through names it."""
            blocking, lapsed = undecided_starts.check(doelnaam, now, rows)
            if lapsed is not None:
                lift_notices.append(_undecided_lapse_finding(lapsed))
            if blocking is not None:
                raise _failure(
                    doelnaam,
                    question,
                    _note(tool, _undecided_refusal(blocking), _undecided_evidence(blocking)),
                )

        def _open_phase_failure(doelnaam: str, question: str, open_phase) -> ToolError:
            """The open-phase refusal through `_failure()`, like the
            undecided start above: the same sentence as always, now as one
            finding for this tool with the ledger fact as evidence, never a
            bare string."""
            return _failure(
                doelnaam,
                question,
                _note(tool, _open_phase_refusal(open_phase), _open_phase_evidence(open_phase)),
            )

        def _bevestiger_regel(bevestiger: str | None) -> str:
            """This tool's first gate needs no runner: it names the
            confirmer in its own answer, even when the channel cannot say who
            that was - and then it says so in so many words instead of
            leaving the line out.

            The VALUE, without the word "bevestiger" in front of it.
            It is an `outcome`, and `Answer.to_text()`
            already writes the subject: prepending the word here printed
            "- bevestiger: bevestiger: <waarde>" on
            `onderhoud_backup_maken`. This was fixed by inlining the two
            texts at `onderhoud_upgrade_fase`'s call site, which left the
            same two sentences in two places; both call sites are back on
            this one function now, and both lines are pinned.
            """
            return f"{bevestiger}" if bevestiger else BEVESTIGER_NIET_VASTGELEGD_TEXT

        def _target_for(gegeven: str) -> str:
            """Which allowlist section applies. The caller names it; with exactly
            one configured target the caller may leave it out."""
            gekozen = gegeven.strip()
            namen = allowlist.targets()
            if not namen:
                # `toegestaan: {}` is a valid configuration and means: nothing
                # is allowed. Asking for a `doel` here would point the operator
                # at the one repair that cannot work - there is no name to give.
                raise ToolError(
                    "deze installatie staat geen enkele handeling toe: handelen.toegestaan in de configuratie is leeg"
                )
            if not gekozen:
                if len(namen) == 1:
                    return namen[0]
                # A Refusal, not a ToolError: these two sentences talk about
                # the CONFIGURATION, so they must leave through the same seam
                # as every other refusal. The empty-configuration branch above
                # stays a ToolError - it is a broken installation, not a call
                # this product could have answered.
                raise ActionRefusal("doel-nodig", tool)
            # The resolver the reading tools share: at 'beperkt' the caller
            # names a section by the pseudonym `status_doelen` showed it.
            echt = _resolve_doel(gekozen, namen)
            if echt is None:
                raise ActionRefusal("doel-onbekend", tool)
            return echt

        # The future of the REAL run, once there is one. `_writer_gate` reads
        # it to decide when the lock may go (see there); `work()` fills it.
        write_worker: list = []
        caller: list = []
        audit: dict = {}

        def _audit_begin(arguments: dict) -> None:
            audit.update(
                arguments=arguments, target=None, action_id=None, outcome="mislukt", marker=None, bevestiger=None
            )

        def _proposal_marker() -> str | None:
            # Read before redeem pops the pending entry; never derive it from a code.
            try:
                return confirmations.marker(bevestiging)
            except ConfirmError:
                return None

        async def _present(arguments, code, target_label, shown_target, operator_proposal, marker, section):
            # The Windows window probe must not hold the event loop. Cancellation
            # consumes a proposal that never reached its caller, just like failure.
            try:
                await asyncio.to_thread(
                    code_presenter,
                    tool,
                    shown_target,
                    arguments,
                    code,
                    operator_proposal,
                    marker,
                    section,
                )
            except BaseException as exc:
                try:
                    confirmations.redeem(code, tool, arguments, target_label, section=section)
                except ConfirmError:
                    pass
                if isinstance(exc, asyncio.CancelledError):
                    raise
                if not isinstance(exc, Exception):
                    raise
                if isinstance(exc, MirrorRefused):
                    # The caller reads only CHANNEL_FAILED, the same for every
                    # failing channel; the operator who must update the
                    # presenter reads this ONE fixed line - no code, no section.
                    try:
                        print(f"[codekanaal] {OLD_PRESENTER_MARKER}", file=sys.stderr, flush=True)
                    except OSError:
                        # Accountability, never a gate - the same reason as
                        # the action log's own stderr write.
                        pass
                raise ToolError(CHANNEL_FAILED) from None
            # The code-bound confirmer is consumed only when redeeming the code.
            audit.update(outcome="voorstel", target=shown_target, marker=marker)

        def _report_orphan(
            finished,
            *,
            doelnaam: str,
            target_label: str,
            bevestiger: str | None,
            context_values: tuple[str, ...] = (),
        ) -> None:
            """The outcome of a run whose caller was cancelled.

            It cannot go back to the chat - there is no longer a call to
            answer - and it must not disappear either: the appliance changed.
            So it goes to the server's own log channel (stderr, the only one
            an MCP server may use next to the protocol on stdout), scrubbed
            the same way every other piece of script output is. Never the
            confirmation code: that was spent before the run started and is
            not part of the outcome.
            """
            try:
                done = finished.result()
            except Exception as exc:  # noqa: BLE001 - a log line, never fatal
                print(
                    f"[handeling] {tool}: de aanroeper is afgebroken, de handeling liep door"
                    f" en eindigde met een fout ({type(exc).__name__}). Controleer de appliance.",
                    file=sys.stderr,
                    flush=True,
                )
                return
            # Caller cancellation cannot cancel accounting for a completed run.
            # Apply the same backup read-back decision as the connected path.
            if tool == "onderhoud_backup_maken":
                established = done.ok and readback_ok(done.text, done.object_name)[0]
            elif tool == "config_opslaan":
                established = done.ok and save_readback_ok(done.text)[0]
            else:
                established = done.ok
            register_warning = _write_action_register(
                onderhoud,
                tool=tool,
                doel=doelnaam,
                actieid=done.actie_id,
                uitkomst="geslaagd" if established else "mislukt",
                bevestiger=bevestiger,
                objectnaam=done.object_name,
                doel_vastgesteld=done.target == target_label,
            )
            if register_warning is not None:
                print(
                    f"[handeling] {tool}: actieregister: {register_warning.outcome}. {register_warning.reason}",
                    file=sys.stderr,
                    flush=True,
                )
            if done.ok:
                # The caller was cancelled, but
                # the SHIELDED worker still landed the write on the
                # appliance - the log line a few statements below says so in
                # so many words ("de handeling liep door"). Gated on the
                # orphaned run's OWN success, exactly the way `if not
                # result.ok` gates the caller-present path further down this
                # function: a run that failed changed nothing on the
                # appliance to count, orphaned or not.
                writes_since_scan.record_write()
            # A FAILED run has no actie-id: the script never wrote one, or
            # it wrote no [ACTIEID] marker at all (handelen.perform). Printing
            # the empty value gives an operator "actie-id None" - a Python
            # repr in a log line that is meant to be read as a sentence.
            wie = f"actie-id {done.actie_id}" if done.actie_id else "actie-id onbekend (run mislukt)"
            print(
                f"[handeling] {tool}: de aanroeper is afgebroken, de handeling liep door."
                f" {wie}: {_from_script(done.eindstatus, extra_values=context_values)}",
                file=sys.stderr,
                flush=True,
            )

        async def _upgrade_work(doelnaam: str) -> str:
            """`onderhoud_upgrade_fase`'s OWN two-step flow.

            Shares the target resolution (`doelnaam`, already resolved by
            the caller), the `Refusal`/`ActionError` seam, the confirmation
            store and the code channel with the five tools `work()` below
            still serves - but nothing else: the runner
            (`Invoke-GjkUpgradeFase.ps1`) has its own argument shape (no
            `-Actie`/`-Bundel`), its own preview contract, and - the reason
            this branch exists at all - is never awaited to completion the
            way `perform()` awaits the demo write script. R1 alone measures
            460 s of upload against this tool's own 300 s ceiling
            (`_TIMEOUT_S`, design 3.5), so the CONFIRMED run is started
            detached and this coroutine waits only for the ledger's own
            `fase_gestart` line, at most `START_WAIT_S`.

            The five in-use refusals are split across
            two seams on purpose. The first (an unknown `fase`, or a
            phase-only argument on the wrong phase) is a `Refusal` - an
            ANSWER, masked and rendered exactly like every other refusal on
            this path. The other four (an unidentifiable confirmer, a run
            already open, the soak window, the previous phase not closed)
            are BARE `ToolError`s, never wrapped in `Answer`/`render()`:
            they are operational refusals about the LEDGER, not about an
            appliance object a disclosure level would ever need to mask -
            the same shape `CHANNEL_FAILED` already uses above.
            """
            try:
                validate(tool, {}, target=doelnaam, allowlist=allowlist)
                phase_clean = validate_phase_arguments(action_arguments)
                _audit_begin(phase_clean)
            except ActionRefusal as exc:
                return _rendered(doelnaam, exc.to_answer(), caller_name=exc.value)
            except ActionError as exc:
                raise _failure(
                    doelnaam,
                    f"handeling {tool}",
                    _note(tool, str(exc), "controle van deze aanroep tegen de configuratie"),
                ) from None

            doel_obj = targets.get(doelnaam)
            if onderhoud is None or doel_obj is None:
                raise _failure(
                    doelnaam,
                    f"handeling {tool}",
                    _note(
                        tool,
                        "onderhoud is niet ingesteld voor dit doel",
                        "controle van deze aanroep tegen de configuratie",
                    ),
                )

            execution_attempt = bool(bevestiging.strip())
            fase = phase_clean["fase"]
            # The TARGET's rows, across every run file in the ledger
            # directory - read HERE, before the run name is settled, because
            # R0 needs them to answer "is there already a run of mine open on
            # this box". `_rows_for_target` needs a path only to find the
            # directory; the file it names need not exist yet.
            #
            # STRICT: a ledger DIRECTORY that cannot be
            # listed is not an empty one, and this is the ONE tool that
            # starts appliance work. This read used to stay tolerant here by
            # pointing at the per-line carve-out below, but that carve-out is
            # about per-LINE tolerance, which `read_ledger()` provides
            # either way - a directory that cannot be listed is a different
            # fact. Zero rows passed BOTH weigering 2 (open phase) and
            # weigering 3 (soak) silently: exactly the fail-open shape this
            # strictness closes. A partly corrupt ledger still cannot
            # brick a running upgrade - `read_ledger()` skips a bad LINE
            # with a warning, and `strict` says nothing about that.
            try:
                target_lines = _rows_for_target(
                    onderhoud.ledgermap / "_.jsonl",
                    doelnaam,
                    strict=True,
                )
            except LedgerUnreadable as exc:
                raise ToolError(
                    f"{exc}, dus of er op dit doel nog een fase open staat is niet vast "
                    "te stellen; deze fase wordt daarom niet gestart"
                ) from None
            # An undecided start on this target refuses the PROPOSAL too,
            # before any preview runs or any code exists - fail-closed, the
            # way the other writing tools already refuse their proposal on
            # an open phase. The confirmed call meets the same register at
            # the open-phase gate below (weigering 2), after the redeem.
            if not execution_attempt:
                _undecided_gate(doelnaam, f"voorstel {tool}", datetime.now(UTC), target_lines)
            # Measured: the soak window used to be checked only at
            # EXECUTION (weigering 2 en 3, further down) - a fresh VOORSTEL
            # minted a code regardless, and that code then burned silently
            # the moment its confirmation hit the same gate: the operator
            # could never redeem it. Refusing it here too, before
            # `confirmations.issue()` ever runs, means a voorstel inside the
            # window gives no code and no "voorstel" action-log line at all.
            # Only on the FRESH-PROPOSAL leg (`not execution_attempt`): the
            # EXECUTION check below stays exactly as is and is not replaced
            # by this one - it is what still catches a window that opens
            # BETWEEN a valid proposal and its confirmation ("dubbel is hier
            # goed: de uitvoering is de waarheid").
            if not execution_attempt:
                voorstel_moment = datetime.now(UTC)
                soak_bij_voorstel = soak_gate(
                    target_lines,
                    voorstel_moment,
                    onderhoud.soak_uren,
                )
                if soak_bij_voorstel.outcome != "open":
                    # The lift notice is a PURE
                    # READING (`expired_phases`, nothing is written) - the
                    # EXECUTION leg already appends it to every bare
                    # ToolError refusal it raises (`_with_lift_notices`,
                    # further down), and this voorstel-time refusal is the
                    # same kind of bare ToolError. Without this, an operator
                    # whose target ALSO carried a phase that expired
                    # (`mislukt`, reden `tijdslimiet`) learned that only
                    # after the soak window itself lifted - SECURITY.md's
                    # "de weigering verdwijnt niet stilzwijgend" promise is
                    # about the LIFT, not only about which gate happens to
                    # fire first.
                    lift_notices.extend(_lift_findings(expired_phases(target_lines, voorstel_moment)))
                    raise ToolError(_with_lift_notices(soak_bij_voorstel.reason))
            # A stale R0 used to be the one state
            # nothing could clear. R1-R6 may name the open run and retry it,
            # but R0 minted a FRESH run id on every call, so the open-run
            # refusal below always fired and R0 could never re-close what it
            # opened - a permanent lock on the very phase that creates a run.
            # R0 now ADOPTS an open R0 on this target instead of minting a
            # second run beside it; only a target with no open R0 gets a new
            # run id. Symmetry with R1-R6, not a new escape: the same rule
            # ("the same run may be retried") applied to the one phase that
            # could not name its run, because it is the phase that makes it.
            #
            # Adoption is BOUNDED BY THE CEILING.
            # `open_phases()` used to be called with no clock here, so every
            # open phase came back `expired=False` and R0 adopted ANY open
            # R0 on this target - including one that started a second ago.
            # `run_name` then equalled the adopted run, the open-phase
            # refusal below did not fire, `order_gate("R0", ...)` is `open`
            # unconditionally, and a SECOND runner was launched against the
            # same appliance and the same ledger file. Only a stale R0 - one
            # past its ceiling, which is `mislukt` with reason `tijdslimiet`
            # and not open at all - is adopted; a LIVE one keeps refusing.
            # That is also what HANDLEIDING.md and SECURITY.md describe: an
            # escape from a phase that never closes, never permission to
            # join one that is running.
            adoption_moment = datetime.now(UTC)
            open_r0 = next(
                (f.run for f in open_phases(target_lines, adoption_moment) if f.phase == "R0" and f.expired),
                None,
            )
            run_name = (open_r0 or run_id(doelnaam, datetime.now(UTC))) if fase == "R0" else phase_clean["run"]
            # BELT: `run_name` becomes a filesystem path stem two lines
            # down (`build_upgrade_arguments()`'s own `-Ledger` argument)
            # and again below (`ledger_path`) - checked here, before
            # EITHER construction runs and before the faserunner is ever
            # invoked, not only at the second of those two.
            #
            # `phase_clean["run"]` (R1..R6) already passed this exact check
            # in `validate_phase_arguments()` above, so this branch is
            # unreachable for it in practice - what it guards in practice is
            # `run_name` itself: either `open_r0`, a run name ADOPTED
            # straight out of a ledger ROW, never typed by the operator, or
            # a FRESH `run_id(doelnaam, ...)` for a new R0.
            #
            # This comment
            # used to claim `run_id()` itself cannot produce an unsafe
            # value because "`doelnaam` is already `validate()`-checked
            # appliance-object grammar" - FALSE. `validate()` (handelen.py)
            # checks NITRO OBJECT arguments (a certnaam, say); `doelnaam`
            # here is a TARGET name, resolved by `_target_for()` above,
            # which only checks that it is one of the CONFIGURED names,
            # never that its own characters are safe. A target called
            # `lab 02` or `ns:01` makes `run_id()` build a stem this
            # product's own run-name grammar rejects. What actually keeps
            # that safe today is `start._require_safe_upgrade_target_
            # names()`, a configuration-READ-time refusal, scoped to
            # exactly the targets the allowlist grants this tool to - this
            # check stays regardless, as the BELT for the ledger-adoption
            # path above, which no start-time check can cover (a ledger
            # row's `run` field is written after the server has already
            # started).
            # `run_name` is NEVER echoed here: it is ledger content on the
            # adoption path, and the binding rule for this whole tool is
            # that ledger strings are untrusted and never echoed raw.
            if not is_safe_run_name(run_name):
                raise ToolError(RUN_NAAM_ONVEILIG_TEXT)

            def _preview_failed(detail: str) -> ToolError:
                return _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        f"De handeling is niet uitgevoerd: de controle vooraf mislukte "
                        f"({detail}). De bevestigingscode is niet ingewisseld en er is niets "
                        "gewijzigd.",
                        "de controle vooraf (-WatIs) van de faserunner",
                    ),
                )

            # `build_upgrade_arguments()` itself can
            # raise `ActionError` - `_firmware_target_build()` refuses an
            # empty, doubly-filled or non-matching firmware directory with an
            # honest sentence (handelen.py). That call used to sit OUTSIDE
            # every local `try` here, so the sentence never reached the
            # operator: it ran on into `_guarded_async`'s bare `except
            # Exception -> mask_error()` and came out as the generic
            # "Onverwachte fout" text - an empty or doubly-filled firmware
            # directory, the most likely misconfiguration in this whole
            # chapter, was undiagnosable. `str(exc)` (not `type(exc).__name__`
            # as the subprocess-failure branch below uses) so the honest
            # sentence itself, not just the exception's class name, reaches
            # the operator.
            # R0's floor gate: the floor and the current build of THIS export,
            # the floor from the knowledge package, computed here at the
            # proposal and again at the execution below - never carried over
            # from one to the other. An export of another target (or of none)
            # is refused here, before the preview and before any code exists
            # or is redeemed - on the execution call with the note that the
            # code is still good.
            try:
                vloer, huidig, vloer_kennis = _upgrade_floor(doelnaam)
            except ToolError as exc:
                if not execution_attempt:
                    raise
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(tool, EXPORTDOEL_VOOR_INWISSELEN_TEXT.format(reden=exc), VERVANGEN_DOEL_EVIDENCE),
                ) from None
            try:
                preview_args = build_upgrade_arguments(
                    phase_clean,
                    target=doel_obj,
                    onderhoud=onderhoud,
                    run_name=run_name,
                    actie_id="",
                    bevestiger=None,
                    preview=True,
                    export_dir=export_dir,
                    forbidden_addresses=forbidden_addresses,
                    floor_build=vloer.build or "",
                    floor_bulletin=vloer.bulletin,
                    current_build=huidig.build or "",
                    floor_package=getattr(vloer_kennis, "version", None) or "",
                    floor_package_date=getattr(vloer_kennis, "date", None) or "",
                )
            except ActionError as exc:
                if execution_attempt:
                    raise _preview_failed(_firmware_reason(exc)) from None
                raise _failure(
                    doelnaam,
                    f"voorstel {tool}",
                    _note(
                        tool,
                        f"voorstel kon niet worden opgesteld: {_firmware_reason(exc)}",
                        "de argumentopbouw van de faserunner",
                    ),
                ) from None
            # The acceptance of this call, as it really travels: the argument
            # builder keeps it back when the floor or the current build is
            # known but has no runner form. Asked for and kept back is refused
            # here, at the proposal and at the execution alike, before any
            # runner starts or any code is redeemed.
            acceptatie_reist = "-DoelbuildGeaccepteerd" in preview_args
            if phase_clean.get("doelbuild_geaccepteerd") and not acceptatie_reist:
                raise ToolError(DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT)
            # The run binding, at the PROPOSAL: R1..R6 install what R0 of this
            # run judged. Only a readable, different target build refuses
            # here, before a code exists; an absent or unreadable one is left
            # to the strict check at the execution (the soak split again).
            if fase != "R0" and not execution_attempt:
                try:
                    voorstel_pad = ledger_path_for(onderhoud.ledgermap, run_name)
                    voorstel_regels = read_ledger(voorstel_pad) if voorstel_pad.exists() else ()
                except (ValueError, OSError):
                    voorstel_regels = ()
                weigering = run_binding_refusal(
                    voorstel_regels,
                    run_name,
                    doelnaam,
                    _argument_value(preview_args, "-Doelbuild") or "",
                    strict=False,
                )
                if weigering is not None:
                    lift_notices.extend(_lift_findings(expired_phases(target_lines, datetime.now(UTC))))
                    raise ToolError(_with_lift_notices(weigering))
            try:
                exit_code, stdout, stderr = await asyncio.to_thread(
                    run_upgrade_preview,
                    preview_args,
                    runner=onderhoud.runner,
                )
            except Exception as exc:
                # 1.1: the preview meets a changed script, a missing
                # PowerShell or an unusable working directory FIRST - on the
                # proposal and on the confirmed call alike - so it names the
                # same fixed sentence as the start does, on the type of the
                # error. Anything else keeps its class name; never its text.
                detail = _not_started_sentence(exc) or type(exc).__name__
                if execution_attempt:
                    raise _preview_failed(detail) from None
                raise _failure(
                    doelnaam,
                    f"voorstel {tool}",
                    _note(
                        tool,
                        f"voorstel kon niet worden opgesteld: {detail}",
                        "de controle vooraf (-WatIs) van de faserunner",
                    ),
                ) from None

            text = stdout if not stderr else f"{stdout}\n{stderr}"
            target_label = _marker(stdout, "[TARGET]")
            actie_id_voorstel = _marker(stdout, "[ACTIEID]")
            # `perform()` (handelen.py) already refuses when the
            # write script's own preview gives no actie-id OR no doel ("het
            # schrijfscript gaf geen actie-id of doel terug") - this path
            # checked only `target_label`. Without `actie_id_voorstel` too,
            # a confirmed call built `-Actieid`-less real arguments
            # (`build_upgrade_arguments()` only adds `-Actieid` `if
            # actie_id:`), and the REAL runner then refuses per its own
            # documented contract (`scripts/README.md`: exit 1, no ledger
            # line) - but only AFTER the full `START_WAIT_S` wait, reporting
            # "geen regel fase_gestart" instead of the real cause. Checking
            # it here, together with `target_label`, fails closed
            # immediately with the honest detail instead.
            if exit_code != 0 or not target_label or not actie_id_voorstel:
                # Measured (17-9-2026): the marker
                # used to be picked BEFORE `_from_script()` ever ran (`or`
                # short-circuits the moment `_marker(...)` finds one), so a
                # [GEWEIGERD] line skipped the masking a marker-less line on
                # the exact same text would have gone through. The selected
                # text - marker or raw - now goes through `_from_script()`
                # either way.
                detail = _from_script(_marker(stdout, "[GEWEIGERD]") or text.rstrip()) or f"exitcode {exit_code}"
                if execution_attempt:
                    raise _preview_failed(detail)
                raise _failure(
                    doelnaam,
                    f"voorstel {tool}",
                    _note(
                        tool,
                        f"voorstel kon niet worden opgesteld: {detail}",
                        "de controle vooraf (-WatIs) van de faserunner",
                    ),
                )

            if not execution_attempt:
                try:
                    code = confirmations.issue(tool, phase_clean, target_label, section=doelnaam)
                except ConfirmError as exc:
                    raise _failure(
                        doelnaam,
                        f"voorstel {tool}",
                        _note(tool, str(exc), "het aantal openstaande voorstellen"),
                    ) from None
                try:
                    marker = confirmations.marker(code)
                except ConfirmError:
                    try:
                        confirmations.redeem(code, tool, phase_clean, target_label, section=doelnaam)
                    except ConfirmError:
                        pass
                    raise ToolError(CHANNEL_FAILED) from None
                shown_target = _from_script(target_label)
                voorstel = Answer(
                    question=f"voorstel {tool}",
                    findings=[
                        Finding(
                            subject=tool,
                            outcome=f"VOORSTEL ({tool}), er is nog niets gewijzigd",
                            certainty=Certainty.ESTABLISHED,
                            evidence="de controle vooraf (-WatIs) van de faserunner",
                            subject_is_name=False,
                        ),
                        Finding(
                            subject="doel",
                            outcome=shown_target,
                            certainty=Certainty.ESTABLISHED,
                            evidence="de faserunner meldde dit doel zelf met [TARGET]",
                            subject_is_name=False,
                        ),
                        Finding(
                            subject="fase",
                            outcome=fase,
                            certainty=Certainty.ESTABLISHED,
                            evidence="argument van deze aanroep",
                            subject_is_name=False,
                        ),
                        Finding(
                            subject="bevestigingscode",
                            outcome=(
                                f"aan de beheerder getoond ({_channel_label}) - vraag de "
                                "beheerder om de code en roep deze tool opnieuw aan met "
                                "bevestiging=<code>"
                            ),
                            certainty=Certainty.ESTABLISHED,
                            evidence=(
                                "De code is tien minuten geldig en werkt een keer, en staat niet in dit antwoord."
                            ),
                            subject_is_name=False,
                        ),
                        # R1 only, and appended after the fixed lines so no
                        # pinned prefix of this proposal moves.
                        *(_r1_drift_voorstel_findings(doelnaam) if fase == "R1" else []),
                        # Every phase, last: the current build, the target
                        # build and the floor with R0's verdict on it, so a
                        # target build below the floor is chosen before the
                        # window, not read afterwards off a closed gate.
                        *proposal_floor_findings(
                            _firmware_bundle_or_reason(),
                            vloer,
                            vloer_kennis,
                            huidig=huidig,
                            geaccepteerd=acceptatie_reist,
                        ),
                    ],
                )
                proposal = _stamped(voorstel).to_text()
                # The operator's own channel gets the real, unsuppressed
                # target label - a human confirming a physical action must
                # see what he is confirming. The model's "doel" Finding
                # above (`shown_target`) keeps the seam's default
                # suppression below 'volledig'.
                await _present(
                    phase_clean,
                    code,
                    target_label,
                    _from_script(target_label, for_operator=True),
                    proposal,
                    marker,
                    doelnaam,
                )
                return _with_marker(_rendered(doelnaam, voorstel, caller_name=None), marker)

            audit.update(marker=_proposal_marker())
            try:
                confirmations.redeem(bevestiging, tool, phase_clean, target_label, section=doelnaam)
            except ConfirmError as exc:
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(tool, str(exc), "de bevestigingscode is getoetst aan het voorstel"),
                ) from None
            mark_spent = getattr(code_presenter, "spent", None)
            if mark_spent is not None:
                try:
                    mark_spent(bevestiging)
                except Exception:  # noqa: BLE001 - never fatal after a redeem
                    pass
            # The comment used to contradict the code: the
            # fallback used to read `getattr(code_presenter, "bevestiger",
            # None)` - exactly the bare attribute the comment below says
            # this seam never reads. No shipped channel carries a bare
            # `.bevestiger` string today, so nothing shipped could pass the
            # gate wrongly - but a FUTURE presenter that does would have
            # slipped through it without code binding. The fallback is now
            # the same honest `None` `bevestiger_for(bevestiging)` itself
            # falls back to when a channel offers neither.
            bevestiger_for = getattr(code_presenter, "bevestiger_for", None)
            bevestiger = bevestiger_for(bevestiging) if bevestiger_for is not None else None
            audit.update(bevestiger=bevestiger)
            # Weigering 1. AFTER redemption, deliberately: a
            # code always gets spent once presented, whether the action
            # this call still refuses to start or not - the same rule
            # `CHANNEL_FAILED` above already lives by. `venster`/`bestand`
            # cannot name a confirmer at all; only `sso` can, and only via
            # `bevestiger_for(bevestiging)` (see mcp_server module
            # docstring and code_channel.SsoCodeChannel) - never the bare
            # `.bevestiger` attribute, which answers for whichever proposal
            # this ONE channel instance delivered LAST, not for the code
            # THIS call just redeemed.
            if bevestiger is None:
                raise ToolError(
                    "de faserunner weigert te starten op een kanaal dat de bevestiger niet kan identificeren"
                )

            # Weigering 2 en 3: the OPEN-RUN check and the SOAK
            # check both bind the TARGET, across every run file in the
            # ledger directory - not only this run's own (possibly not yet
            # existing) file (`target_lines`, read above).
            #
            # Age-bounded, and for the same
            # reason the cross-tool gate is: a phase past its ceiling with no
            # closing row is `mislukt` with reason `tijdslimiet`, not open.
            # Without that, a stale phase of a FOREIGN run barred every new
            # run on this target forever, with the retry escape available
            # only to the run that already owned it.
            #
            # `blocking_phase` scans EVERY open phase of the target, the
            # caller's own run included (a later fix:
            # `blocking_phase()` used to take an `except_run=run_name` that
            # skipped every non-expired open phase of the run being called -
            # a live phase of the caller's OWN run could not block a second
            # invocation of that same run, and this product cannot stop or
            # even observe a detached faserunner to tell that second
            # invocation apart from a genuine second writer. Only an
            # EXPIRED phase - of any run - is not "still blocking";
            # `blocking_phase()` already applies that ceiling check on its
            # own, so nothing further is needed here).
            #
            # BRACES: `run_name` is already checked BELT-safe above (and,
            # for R1..R6, in `validate_phase_arguments()` before that) -
            # `ledger_path_for()` (nsmcp.upgrade) resolves the path this
            # construction would build and refuses unless it still sits
            # inside `onderhoud.ledgermap`, so a value that somehow got
            # past both of those still cannot write or read outside it.
            try:
                ledger_path = ledger_path_for(onderhoud.ledgermap, run_name)
            except ValueError:
                raise ToolError(LEDGERPAD_BUITEN_LEDGERMAP_TEXT) from None
            gate_moment = datetime.now(UTC)
            # The register first: a start this server launched but could not
            # see land holds the target even though the ledger is empty.
            _undecided_gate(doelnaam, f"uitvoering {tool}", gate_moment, target_lines)
            open_phase = blocking_phase(target_lines, gate_moment)
            if open_phase is not None:
                raise _open_phase_failure(doelnaam, f"uitvoering {tool}", open_phase)
            lift_notices.extend(_lift_findings(expired_phases(target_lines, gate_moment)))
            soak = soak_gate(target_lines, gate_moment, onderhoud.soak_uren)
            if soak.outcome != "open":
                raise ToolError(_with_lift_notices(soak.reason))

            # Weigering 4: the ORDER check is scoped to THIS
            # run's OWN file only - unlike the two above, it must not see a
            # different run's leftover phase state.
            run_regels = read_ledger(ledger_path) if ledger_path.exists() else ()
            orde = order_gate(fase, run_regels)
            if orde.outcome != "open":
                raise ToolError(_with_lift_notices(orde.reason))

            # A later fix: refuse a RE-RUN of an already
            # CLOSED phase here, before the runner is ever launched - a
            # gap in what `order_gate` above covers, which checks only the
            # PREVIOUS phase, which is by definition already closed once
            # this phase itself was ever reached, so a retry of THIS phase
            # sailed through every check above (`blocking_phase` sees the
            # closing row as not open; `order_gate` is silent on this
            # phase's own history) and reached `start_detached()` - which
            # for R1 re-uploads the bundle and for R3 re-runs `installns -Y
            # -n` - before `upgrade_gate.main()`'s `ClosedPhaseError`
            # finally refused it, AFTER the appliance work, appending NO
            # closing row. The ledger's last row for the phase then became
            # that fresh, unfinished start row - OPEN under
            # `open_phases()`'s last-row rule - locking every writing tool
            # on the target for the phase's full ceiling with no way to
            # close it inside this run (recovery: wait out the ceiling,
            # start an entirely new run).
            #
            # `phase_has_closing_row(run_regels, fase)`, never
            # `phase_state()`/`order_gate()`: the same "ANY closing row
            # anywhere in this run's file, not just the LAST row" question
            # `upgrade_gate.main()` already asks, and for the identical
            # reason - the runner always writes a fresh `fase_gestart` row
            # before ever invoking `upgrade_gate`, so the LAST row for this
            # phase is, by construction, always that fresh start row once a
            # retry is attempted (`phase_has_closing_row()`'s own
            # docstring). `run_regels` is THIS run's own file, already read
            # above for weigering 4 - the same scope this check needs.
            if phase_has_closing_row(run_regels, fase):
                raise ToolError(_with_lift_notices(FASE_AL_GESLOTEN_TEXT))

            # The SAME honest `ActionError` as the
            # preview call above - AFTER redeem here, so the code is already
            # spent and the operator must be told nothing started, not read
            # the generic "Onverwachte fout" text. The same holds for an export
            # that no longer describes this target: a scan can land between
            # the preview and this read, and the code is spent by now.
            try:
                vloer, huidig, vloer_kennis = _upgrade_floor(doelnaam)
            except ToolError as exc:
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        EXPORTDOEL_NA_INWISSELEN_TEXT.format(reden=exc),
                        EXPORTDOEL_NA_INWISSELEN_EVIDENCE,
                    ),
                ) from None
            try:
                real_args = build_upgrade_arguments(
                    phase_clean,
                    target=doel_obj,
                    onderhoud=onderhoud,
                    run_name=run_name,
                    actie_id=actie_id_voorstel or "",
                    bevestiger=bevestiger,
                    preview=False,
                    export_dir=export_dir,
                    forbidden_addresses=forbidden_addresses,
                    floor_build=vloer.build or "",
                    floor_bulletin=vloer.bulletin,
                    current_build=huidig.build or "",
                    floor_package=getattr(vloer_kennis, "version", None) or "",
                    floor_package_date=getattr(vloer_kennis, "date", None) or "",
                )
            except ActionError as exc:
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        f"De handeling is niet gestart: de argumentopbouw mislukte ({_firmware_reason(exc)}). De "
                        "bevestigingscode is verbruikt.",
                        "de argumentopbouw van de faserunner",
                    ),
                ) from None
            # The run binding, at the EXECUTION and strict: the bundle this
            # runner is about to get (`-Doelbuild` of the arguments just
            # built) must be the one R0 of this run started with, as its own
            # file records it (`run_regels`, already read for the order
            # gate). Unreadable or absent there is a refusal too.
            if fase != "R0":
                weigering = run_binding_refusal(
                    run_regels,
                    run_name,
                    doelnaam,
                    _argument_value(real_args, "-Doelbuild") or "",
                    strict=True,
                )
                if weigering is not None:
                    raise ToolError(_with_lift_notices(weigering))

            def _niet_gestart(soort: str | None) -> ToolError:
                # `None`: an error of no known type - the general sentence,
                # never the text of the error.
                reden = RUNNER_NIET_GESTART_ALGEMEEN if soort is None else RUNNER_NIET_GESTART_REDEN.format(soort=soort)
                return _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        EXPORTDOEL_NA_INWISSELEN_TEXT.format(reden=reden),
                        RUNNER_NIET_GESTART_EVIDENCE,
                    ),
                )

            # 1.1: mapped on TYPE, specific before general (both are
            # subclasses of `PowerShellMissing`). Nothing is held yet here,
            # so there is nothing to release: no child was started.
            try:
                argv = upgrade_command(onderhoud.runner, real_args)
            except ScriptPinMismatch as exc:
                audit.update(oorzaak=_not_started_cause(exc))
                raise _niet_gestart(RUNNER_NIET_GESTART_SCRIPTPIN) from None
            except ChildWorkingDirectoryUnusable as exc:
                audit.update(oorzaak=_not_started_cause(exc))
                raise _niet_gestart(RUNNER_NIET_GESTART_WERKMAP) from None
            except PowerShellMissing as exc:
                audit.update(oorzaak=_not_started_cause(exc))
                raise _niet_gestart(RUNNER_NIET_GESTART_POWERSHELL) from None
            log_path = ledger_path.with_suffix(".log")
            # How many `fase_gestart` rows this
            # run/phase ALREADY has, counted BEFORE the runner is launched. A
            # retry - the documented escape from a phase that never closed,
            # and now R0's adopted run as well - would otherwise match the
            # PREVIOUS attempt's row instantly and report FASE GESTART for a
            # runner that never wrote a line.
            already_started = await asyncio.to_thread(
                started_rows,
                ledger_path,
                run_name,
                fase,
            )
            audit.update(outcome="onbekend")
            wait_s = START_WAIT_S
            launched = datetime.now(UTC)

            def _undecided_start(*, broke_off: bool, waiting_until: datetime | None = None) -> UndecidedStart:
                return UndecidedStart(
                    target=doelnaam,
                    run=run_name,
                    phase=fase,
                    launched=launched,
                    ledger_path=ledger_path,
                    already_started=already_started,
                    wait_s=wait_s,
                    broke_off=broke_off,
                    waiting_until=waiting_until,
                )

            def _hold_target(*, broke_off: bool) -> UndecidedStart:
                """A runner may exist and may still write its row: the target
                is held in the register until that row lands or the phase's
                time limit passes."""
                entry = _undecided_start(broke_off=broke_off)
                undecided_starts.record(entry)
                return entry

            # The target is held from the moment the start is REQUESTED, not
            # from the moment `start_detached()` returns: a call cancelled
            # while the launch runs in its worker thread (`notifications/
            # cancelled`, an interrupt) unwinds this coroutine, but the
            # thread finishes the launch - a runner exists that nothing here
            # held the target for. While this call still runs, the entry
            # says the server still waits for the row (`waiting_until`), not
            # that the wait broke off: measured, another caller and the
            # stand read "brak af [vastgesteld]" for a wait that was still
            # running, and seconds later the same call answered FASE
            # GESTART. Every way out of this call replaces that entry: a
            # cancellation or any other exception with `broke_off`, a
            # timeout with the waited-out entry, a decided start with
            # nothing. Only one of the three TYPED errors takes the hold
            # back - `start_detached()` raises them only when it is proven
            # that no child exists (the working directory was unusable or
            # the log file did not open, both before `Popen`, or `Popen`
            # failed on every attempt) - and `withdraw()` then restores what
            # the register held before. 1.1: an `ActionError` of any other
            # type no longer counts as that proof: the general sentence,
            # without its text, and the target stays held (fail-closed).
            requested = _undecided_start(broke_off=False, waiting_until=launched + timedelta(seconds=wait_s))
            replaced = undecided_starts.record(requested)

            def _released(exc: ProcessNotStarted, sentence: str) -> ToolError:
                undecided_starts.withdraw(requested, replaced)
                audit.update(outcome="mislukt", oorzaak=_not_started_cause(exc))
                return _niet_gestart(sentence)

            try:
                runner_host = await asyncio.to_thread(start_detached, argv, log_path=log_path)
            except RunnerWorkdirUnusable as exc:
                raise _released(exc, RUNNER_NIET_GESTART_WERKMAP) from None
            except RunnerLogUnopenable as exc:
                raise _released(exc, RUNNER_NIET_GESTART_LOGBESTAND) from None
            except RunnerProcessNotStarted as exc:
                raise _released(exc, RUNNER_NIET_GESTART_PROCES) from None
            except ActionError as exc:
                _hold_target(broke_off=True)
                audit.update(oorzaak=_not_started_cause(exc))
                raise _niet_gestart(None) from None
            except BaseException:
                # Cancelled or interrupted during the launch: the thread may
                # still finish it, so the target stays held - as a wait that
                # broke off, never as one that still runs.
                _hold_target(broke_off=True)
                raise

            # The launch returned; the wait starts now, so the entry says
            # until when from here on (`wait_for_start` counts its own
            # `wait_s` from the moment it is called, just after this).
            undecided_starts.record(
                _undecided_start(broke_off=False, waiting_until=datetime.now(UTC) + timedelta(seconds=wait_s))
            )
            try:
                gestart = await asyncio.to_thread(
                    wait_for_start,
                    ledger_path,
                    run_name,
                    fase,
                    wait_s,
                    already_started,
                )
            except BaseException:
                # The wait itself failed or was cancelled (an unreadable run
                # file, a client that stopped waiting): the runner was still
                # launched, so the target is held exactly as on a timeout -
                # never left open because the WAIT, not the runner, fell over.
                _hold_target(broke_off=True)
                raise
            if gestart is None:
                # `start_detached()` above already launched the child and
                # this coroutine does not - and, being detached
                # (DETACHED_PROCESS/CREATE_NEW_PROCESS_GROUP on Windows,
                # start_new_session elsewhere), CANNOT - stop it. A timeout
                # here says only that the LEDGER stayed silent, never that
                # the process did too; saying so plainly instead of
                # implying the attempt is simply over. The target stays held
                # (`_hold_target`), and the answer says until when.
                entry = _hold_target(broke_off=False)
                raise ToolError(
                    _with_lift_notices(
                        f"de fase heeft binnen {wait_s} seconden geen regel fase_gestart in "
                        "het ledger geschreven; de fase telt niet als gestart. De faserunner is "
                        "losgekoppeld gestart en kan nog steeds draaien; dit product kan dat proces "
                        "niet stoppen - vraag de stand na met onderhoud_upgrade_stand voor u opnieuw "
                        "probeert."
                        + ONBESLIST_TIMEOUT_TEXT.format(
                            fase=entry.phase,
                            limiet=entry.limit_s,
                            deadline=_moment(entry.deadline),
                        )
                        + _stand_hint()
                    )
                )
            # A decided start: whatever this target held before (a start
            # that lapsed at its limit) is replaced by the ledger's own row.
            undecided_starts.discard(doelnaam)

            # A phase that really started changed the appliance's
            # maintenance state, so the freshness counter counts it too -
            # the same rule every other write tool's SUCCESS path follows.
            writes_since_scan.record_write()
            # The
            # five FASE-GESTART lines stay behind the openness seam (a bare
            # string here would be the one text in this whole write path
            # that skips render() - see the module docstring above), but the
            # wording is now as close to those five lines as the seam
            # allows, and this exact text is PINNED byte-for-byte in
            # tests/test_product_surface.py. Two adjustments from before:
            # a full stop after "(onderhoud_upgrade_fase)", and the
            # "bevestiger" outcome carries ONLY the value -
            # `_bevestiger_regel()` used to prepend "bevestiger: ", which
            # doubled the word next to this Finding's own "bevestiger: "
            # subject prefix (`to_text()`'s `- <subject>: <outcome>` shape);
            # that prefix was taken out of the function itself, so both
            # write paths share the one implementation again.
            # The fallback text stays reachable in principle (defensive,
            # fail-closed) even though `bevestiger` is already proven
            # non-None by the identity gate above.
            fase_antwoord = Answer(
                question=f"uitvoering {tool}",
                findings=[
                    Finding(
                        subject=tool,
                        outcome=f"FASE GESTART ({tool}).",
                        certainty=Certainty.ESTABLISHED,
                        evidence=f"regel fase_gestart in het ledger, run {run_name}",
                        subject_is_name=False,
                    ),
                    Finding(
                        subject="run",
                        outcome=run_name,
                        certainty=Certainty.ESTABLISHED,
                        evidence="run-id van deze upgrade",
                        subject_is_name=False,
                    ),
                    Finding(
                        subject="fase",
                        outcome=fase,
                        certainty=Certainty.ESTABLISHED,
                        evidence="argument van deze aanroep",
                        subject_is_name=False,
                    ),
                    Finding(
                        subject="oordeel",
                        outcome=(
                            "Het oordeel over deze fase komt uit het ledger, niet uit dit "
                            "antwoord. Vraag het na met onderhoud_upgrade_stand."
                        ),
                        certainty=Certainty.ESTABLISHED,
                        evidence="ontwerp 3.5, de ledger is de waarheid",
                        subject_is_name=False,
                    ),
                    Finding(
                        subject="bevestiger",
                        outcome=_bevestiger_regel(bevestiger),
                        certainty=Certainty.ESTABLISHED,
                        evidence=("wat het codekanaal over de bevestiger kon zeggen bij het inwisselen van de code"),
                        subject_is_name=False,
                    ),
                    # Integration on the release (14-9-2026): the runner's
                    # lifetime is MEASURED at the start (Job Object breakaway,
                    # `handelen.start_detached`), never assumed - and it comes
                    # AFTER the pinned prefix, so the five FASE-GESTART lines
                    # (tests/test_product_surface.py) stay byte-for-byte.
                    Finding(
                        subject="faserunner",
                        outcome=runner_host,
                        certainty=(
                            Certainty.NOT_ESTABLISHED
                            if runner_host == RUNNER_NIET_BEOORDEELD
                            else Certainty.ESTABLISHED
                        ),
                        evidence="IsProcessInJob op het gestarte proces, gemeten bij de start",
                        reason=(
                            "Windows gaf geen uitsluitsel over de Job Object-binding van de faserunner"
                            if runner_host == RUNNER_NIET_BEOORDEELD
                            else ""
                        ),
                        subject_is_name=False,
                    ),
                ],
            )
            audit.update(outcome="gestart", target=_from_script(target_label), action_id=actie_id_voorstel)
            return _rendered(doelnaam, fase_antwoord, caller_name=None)

        # Filled by the cross-tool phase gate below when it LIFTS, read by
        # `_rendered()` above. One list per `_act()` call, so it can never
        # leak from one request into another.
        lift_notices: list[Finding] = []

        def _with_lift_notices(message: str) -> str:
            """A bare-`ToolError` refusal that comes AFTER a lifted one still
            says the first one lifted.

            `lift_notices` reaches the operator only
            through `_rendered()` (as findings on an `Answer`), and a bare
            `ToolError` skips that exit - so a phase call that lifted a
            stale refusal and then hit the soak or the order gate threw the
            notice away, and SECURITY.md's promise that "de weigering
            verdwijnt niet stilzwijgend" was not kept on that path. Appended
            and never prepended, for the same reason `_rendered()` appends:
            the refusal's own sentence is product surface and stays the
            first thing the operator reads.
            """
            if not lift_notices:
                return message
            return message + "".join(f" ({finding.outcome})" for finding in lift_notices)

        async def work():
            # "" until _target_for() has spoken, so a refusal from _target_for
            # itself still reaches _rendered() with a target it can look up
            # (an unknown section simply yields no allowlist names).
            doelnaam = ""
            try:
                doelnaam = _target_for(given_target)
                if tool == "onderhoud_upgrade_fase":
                    return await _upgrade_work(doelnaam)
                if disclosure is not Disclosure.FULL:
                    # Below 'volledig' the caller only ever SAW pseudonyms,
                    # and validate() judges real object names. Resolve first,
                    # so the allowlist keeps bounding what may be touched.
                    namen = _write_names(doelnaam)
                    for veld, gegeven in list(action_arguments.items()):
                        echt = resolve_pseudonym(gegeven, namen, pseudonym_table_path)
                        if echt is None:
                            # WHAT the caller handed in decides how this
                            # refusal may speak about it, and the two cases
                            # are opposites.
                            #
                            # A value with the PSEUDONYM SHAPE goes in as
                            # caller_name=None. One refusal for an issued and
                            # an unissued pseudonym alike: the difference must
                            # not be walkable (disclosure.render, same rule),
                            # and handing the typed pseudonym to render()
                            # would raise PseudonymAsInput for an UNISSUED one
                            # ONLY - that difference IS the probe. Echoing it
                            # costs nothing: a pseudonym is this seam's own
                            # word, not a name off the appliance.
                            #
                            # Anything ELSE is a name the caller invented, and
                            # it must NOT come back verbatim - that is the one
                            # promise this level makes. It therefore travels
                            # as `caller_name`, exactly as it does on the
                            # reading path, so `render()` replaces it with its
                            # one fixed text. The normal case, not an edge
                            # case: a certificate uploaded after the last scan
                            # is in neither the allowlist nor the export.
                            #
                            # `echoed_value(gegeven)`, not the raw `gegeven`:
                            # `to_answer()`
                            # renders through `Refusal.sentence()`, which
                            # `!r`-escapes this same value (I-a) - the answer
                            # text below carries THAT spelling, and
                            # `disclosure._limit()` masks by searching the
                            # text for `caller_name` as a literal needle. The
                            # raw value stopped matching the moment sentence()
                            # started escaping it; the needle has to match
                            # what is actually in the text.
                            return _rendered(
                                doelnaam,
                                ActionRefusal(
                                    "niet-toegestaan",
                                    tool,
                                    field=veld,
                                    value=gegeven,
                                ).to_answer(),
                                caller_name=None if has_pseudonym_shape(gegeven) else echoed_value(gegeven),
                            )
                        action_arguments[veld] = echt
                clean = validate(tool, action_arguments, target=doelnaam, allowlist=allowlist)
                _audit_begin(clean)
            except ActionRefusal as exc:
                # A refusal is an ANSWER from here on, not an error: only an
                # answer passes through render(), and a refusal that skips the
                # seam is exactly what a later fix removes. `exc.value` is the value the
                # CALLER supplied, the only name a refusal may carry - handed
                # through `echoed_value()` for the same reason as the
                # pseudonym-resolution loop above:
                # `caller_name` must match the ESCAPED spelling `to_answer()`
                # renders, not the raw value.
                return _rendered(doelnaam, exc.to_answer(), caller_name=echoed_value(exc.value))
            except ActionError as exc:
                raise _failure(
                    doelnaam,
                    f"handeling {tool}",
                    _note(tool, str(exc), "controle van deze aanroep tegen de configuratie"),
                ) from None

            if onderhoud is not None:
                # WHY THE GATE IS HERE AT ALL: `gated_work` below takes the
                # single-writer gate, but `_upgrade_work` returns - and
                # releases it - the moment `fase_gestart` lands in the
                # ledger, while the detached runner still uploads firmware
                # for ~460s. In that window this product's other five write
                # tools knew nothing about the running phase and could still
                # reach the SAME appliance over NITRO. The detached start is
                # plan-mandated and stays; this closes the window it opens,
                # reusing the machinery `onderhoud_upgrade_fase` already runs
                # on ITSELF rather than a new mechanism, per target, before
                # anything is done (proposal included: fail-closed, not only
                # the confirmed path). Scoped to `onderhoud is not None`: a
                # server without that section has no ledger to consult.
                #
                # WHY IT SITS AFTER `validate()`: it used to
                # run before it, so a caller whose allowlist forbids this
                # tool on this target learned "er staat nog een fase open op
                # dit doel" - a fact about that target's maintenance state -
                # instead of the allowlist refusal. The phase tool's own,
                # identical check has always sat after its `validate()`;
                # this one now does too.
                #
                # WHY IT HAS AN EXIT: with no age
                # bound, any `fase_gestart` without a closing row refused
                # every write tool on that target FOREVER, and that state is
                # reachable - `scripts/README.md`'s exit code 3 and a killed
                # detached runner both leave exactly it behind. An open phase
                # past its ceiling is not open: `blocking_phase()` only
                # refuses while `PHASE_LIMITS_S` says the phase could still
                # be running, and `_lift_findings()` makes the lift audible
                # instead of silent.
                #
                # WHY IT READS STRICTLY: a ledger
                # directory this product cannot read is not an empty one. An
                # unreadable ledger used to reopen exactly the window this
                # gate closes; it now refuses instead. `read_ledger`'s
                # per-LINE tolerance is untouched - one corrupt row must
                # never brick a running upgrade.
                #
                # `.ledgermap / "_.jsonl"` need not exist: `_rows_for_target`
                # only reads its PARENT directory.
                try:
                    phase_rows = _rows_for_target(
                        onderhoud.ledgermap / "_.jsonl",
                        doelnaam,
                        strict=True,
                    )
                except LedgerUnreadable as exc:
                    raise ToolError(
                        f"{exc}, dus of er op dit doel nog een fase open staat is niet vast "
                        "te stellen; deze handeling wordt daarom geweigerd"
                    ) from None
                now = datetime.now(UTC)
                # The register of undecided starts first, with the same rows:
                # a phase runner this server launched but did not see write
                # its start row holds the target although the ledger is
                # still empty.
                vraag = f"{'uitvoering' if bevestiging.strip() else 'voorstel'} {tool}"
                _undecided_gate(doelnaam, vraag, now, phase_rows)
                open_phase = blocking_phase(phase_rows, now)
                if open_phase is not None:
                    raise _open_phase_failure(doelnaam, vraag, open_phase)
                lift_notices.extend(_lift_findings(expired_phases(phase_rows, now)))

            # `config_opslaan` saves over SSH on ONE configured box: it needs
            # that box's address, credential target and pinned host key from
            # `doelen`, next to the allowlist section of the same name. Checked
            # after the allowlist and the open-phase gate, like the phase
            # tool's own lookup.
            doel_obj = targets.get(doelnaam) if tool == "config_opslaan" else None
            if tool == "config_opslaan" and (onderhoud is None or doel_obj is None):
                raise _failure(
                    doelnaam,
                    f"handeling {tool}",
                    _note(tool, CONFIG_OPSLAAN_ZONDER_DOEL_TEXT, "controle van deze aanroep tegen de configuratie"),
                )

            def _run_write(preview_run: bool, bevestiger_run: str | None = None):
                """The tool's own executor: `perform_save()` for
                `config_opslaan` (its own SSH script), `perform()` - the demo
                write script - for every other tool on this path. Both return
                the same `ActionResult`, read the same markers and share the
                time limit, so everything around this call stays one path."""
                if tool == "config_opslaan":
                    return perform_save(
                        target=doel_obj,
                        onderhoud=onderhoud,
                        allowlist=allowlist,
                        preview=preview_run,
                        forbidden_addresses=forbidden_addresses,
                        run=action_run,
                        bevestiger=bevestiger_run,
                    )
                return perform(
                    tool,
                    clean,
                    script=action_script,
                    fixture_dir=fixture_dir,
                    preview=preview_run,
                    bundle=bundle_name,
                    target=doelnaam,
                    allowlist=allowlist,
                    run=action_run,
                    bevestiger=bevestiger_run,
                )

            execution_attempt = bool(bevestiging.strip())

            def _preview_failed(detail: str) -> ToolError:
                # Gedeeld door beide takken: dezelfde preview-aanroep opent
                # zowel het voorstel- als het uitvoerpad. Mislukt hij tijdens
                # een uitvoerpoging, dan is de generieke voorstel-tekst
                # misleidend - de aanroeper gaf al een code. `detail` draagt
                # de eindstatus van het schrijfscript en daarmee mogelijk een
                # objectnaam, dus ook deze afloop gaat door de naad.
                return _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        f"De handeling is niet uitgevoerd: de controle vooraf mislukte "
                        f"({detail}). De bevestigingscode is niet ingewisseld en er is niets "
                        "gewijzigd.",
                        "de controle vooraf (-WatIs) van het schrijfscript",
                    ),
                )

            try:
                preview = await asyncio.to_thread(_run_write, True)
            except ActionRefusal as exc:
                # `Refusal` is a SUBCLASS of `ActionError`
                # (handelen.py, design 3.3), so WITHOUT this clause a refusal
                # raised out of `perform()` fell straight into the plain
                # `except ActionError` just below it - the ORDER of these
                # except-clauses IS the contract here, exactly as it already
                # is above this try-block (`except ActionRefusal` before
                # `except ActionError` there too). A refusal reaching here
                # comes from build_arguments()'s own (second) `validate()`
                # call deep inside `perform()` - the SAME `validate()` shape
                # that already ran on `clean` just above this try-block, so
                # `exc.value` carries the same kind of thing it does there:
                # whatever `clean[field]` held. That is safe to hand to
                # `caller_name` here, but NOT because it was "already
                # validated" - a validated value is not automatically a
                # KNOWN one, and a future raiser deeper in this path
                # that hangs an unvalidated value on a `Refusal` here would
                # get no such guarantee from that reasoning alone. The
                # load-bearing fact is narrower: `clean[field]` is, by
                # construction, one of the allowlist's OWN values - the
                # first `validate()` call above lets nothing else through -
                # and `_write_names(doelnaam)` collects precisely those same
                # allowlist values into `extra_names`. So `caller_name` is
                # always a member of `extra_names` here, `render()`'s
                # 'beperkt' branch therefore never treats it as
                # caller-invented (`invented` stays `None`), and
                # `PseudonymAsInput` - raised only for an `invented` value -
                # cannot come from this call site. The
                # `has_pseudonym_shape(...)` nuance that the resolution loop
                # above `_target_for` needs for ITS OWN hand-built Refusal
                # therefore does not belong here either - this route mirrors
                # the plain `except ActionRefusal` a few lines up,
                # unconditionally: `return _rendered(doelnaam,
                # exc.to_answer(), caller_name=echoed_value(exc.value))`.
                #
                # `echoed_value()` here too, for
                # the same reason as the mirrored site above: `to_answer()`
                # renders `exc.value` through `sentence()`'s `!r` escaping,
                # and `caller_name` has to match that spelling for
                # `disclosure._limit()`'s masking to find it. A no-op for
                # `clean[field]` today (it already passed `_NAME`, so
                # `echoed_value` returns it unchanged) - but the caveat
                # two paragraphs up cuts both ways: a future raiser that
                # hangs an UNvalidated value on a `Refusal` here gets the
                # escaping for free instead of silently losing it.
                #
                # Deliberately the SAME handling on both the proposal path
                # and the execution path, unlike `except ActionError` just
                # below: a refusal is an ANSWER (it goes through `_rendered`/
                # `render()`), not an operational failure, so it needs no
                # `_preview_failed()` branch to reassure the caller. That
                # reassurance holds here too without branching on
                # `execution_attempt`: this call is the -WatIs PREVIEW, and
                # every `confirmations.redeem()` call in this function sits
                # further down, AFTER this try-block returns - so a refusal
                # here means any confirmation code already given is untouched
                # (still redeemable) and nothing was written, on either path.
                # The code itself never appears in the answer: `Refusal`
                # never carries it, only the refused `field`/`value` off the
                # allowlist check - `to_answer()` composes the weigertekst
                # from those two alone.
                return _rendered(doelnaam, exc.to_answer(), caller_name=echoed_value(exc.value))
            except ActionError as exc:
                # Before this except clause, an
                # ActionError raised INSIDE perform() (via build_arguments(),
                # e.g. backup_name() refusing a target that bypassed
                # start.py's startup gate) fell through to the generic
                # `except Exception` below, which re-raises it unchanged for
                # a proposal (`execution_attempt` False) - straight past
                # `_guarded_async`'s own generic `except Exception` into
                # `mask_error()`. The caller then saw the byte-identical
                # masked "Onverwachte fout ..." sentence, even though
                # handelen.py's comment on that branch claimed an honest
                # `ActionError`. Handled the SAME way an `ActionError` from
                # `validate()` above already is on the PROPOSAL path - a
                # configuration problem, not a script failure.
                #
                # A later fix caught ActionError on TYPE, not
                # on its origin, so it also swallowed a raiser this comment
                # never named - default_runner() wrapping an OSError when
                # subprocess.Popen cannot even start the write script. That
                # one fires DURING the write attempt, not before it, so on
                # the EXECUTION path (a confirmation code already given) it
                # is the SAME kind of failure the `except Exception` clause
                # just below already routes through `_preview_failed()`: the
                # reassuring "bevestigingscode niet ingewisseld" sentence and
                # the true "-WatIs" evidence line belong there, and str(exc)
                # is never scrubbed, so it may carry a local path. type(exc)
                # cannot leak anything - it names the raiser, never the
                # message - so it is passed on unchanged, exactly like the
                # `except Exception` branch already does. The PROPOSAL path
                # keeps the honest configuration text unconditionally: it is
                # still where a caller learns their target bypasses the
                # startup gate.
                #
                # 1.1: a TYPED start failure (`config_opslaan` runs its save
                # script through `handelen.typed_runner`) is not a
                # configuration problem: it says why the script did not
                # start, on both paths, with a fixed sentence.
                not_started = _not_started_sentence(exc)
                if execution_attempt:
                    raise _preview_failed(not_started or type(exc).__name__) from None
                if not_started is not None:
                    raise _failure(
                        doelnaam,
                        f"voorstel {tool}",
                        _note(
                            tool,
                            SCRIPT_NIET_GESTART_VOORSTEL_TEXT.format(
                                reden=SCRIPT_NIET_GESTART_REDEN.format(soort=not_started)
                            ),
                            SCRIPT_NIET_GESTART_EVIDENCE,
                        ),
                    ) from None
                raise _failure(
                    doelnaam,
                    f"handeling {tool}",
                    _note(tool, str(exc), "controle van deze aanroep tegen de configuratie"),
                ) from None
            except Exception as exc:
                if execution_attempt:
                    raise _preview_failed(type(exc).__name__) from None
                raise
            target_label = preview.target
            context_values = _context_values_to_mask(target_label)
            if not preview.ok:
                if execution_attempt:
                    raise _preview_failed(_from_script(preview.eindstatus, extra_values=context_values))
                raise _failure(
                    doelnaam,
                    f"voorstel {tool}",
                    _note(
                        tool,
                        "voorstel kon niet worden opgesteld: "
                        f"{_from_script(preview.eindstatus, extra_values=context_values)}",
                        "de regel [EINDSTATUS] van de controle vooraf",
                    ),
                )
            target_label = preview.target

            if not execution_attempt:
                if not target_label:
                    raise _failure(
                        doelnaam,
                        f"voorstel {tool}",
                        _note(
                            tool,
                            "Het voorstel kon niet worden opgesteld: het schrijfscript meldde "
                            "geen doel. Er is geen bevestigingscode uitgegeven en er is niets "
                            "gewijzigd.",
                            "het schrijfscript gaf geen [TARGET]-regel",
                        ),
                    )
                plan_text = "\n".join(
                    regel
                    for regel in preview.text.splitlines()
                    if "zou doen" in regel or regel.startswith("[OK] vangrail")
                )
                plan = _from_script(plan_text, extra_values=context_values)
                if not plan:
                    raise _failure(
                        doelnaam,
                        f"voorstel {tool}",
                        _note(
                            tool,
                            "Het voorstel kon niet worden opgesteld: het schrijfscript meldde "
                            "niet wat het zou doen. Er is geen bevestigingscode uitgegeven en "
                            "er is niets gewijzigd.",
                            "geen enkele regel van de controle vooraf zei wat het zou doen",
                        ),
                    )
                # The operator's own copy of the same plan text: the same
                # credential-/address-masking `_from_script()` always applies,
                # but never the below-'volledig' suppression -
                # `for_operator=True` is the one exception that seam grants,
                # the same one the target label already used further down.
                # The model never reads this value; only the operator's own
                # channel (venster/bestand/SSO) does, via `operator_proposal`.
                operator_plan = _from_script(plan_text, extra_values=context_values, for_operator=True)
                try:
                    code = confirmations.issue(tool, clean, target_label, section=doelnaam)
                except ConfirmError as exc:
                    # A refused 27th simultaneous
                    # proposal (`TooManyProposals`, a `ConfirmError`) is a
                    # designed, expected limit - confirm.py's own docstring
                    # says "Never silent". Without this except clause it fell
                    # through to `_guarded_async`'s generic
                    # `except Exception -> mask_error()` below and reached the
                    # operator as "Onverwachte fout... De details zijn niet
                    # bewaard", which is not even true here: nothing was lost,
                    # this refusal just had no route of its own yet. It takes
                    # the SAME route `ConfirmError` from `redeem()` already
                    # takes further down this function - through `_failure()`,
                    # which comes back out as a `ToolError` and so passes
                    # `mask_error()` unchanged - not a second, invented one.
                    raise _failure(
                        doelnaam,
                        f"voorstel {tool}",
                        _note(tool, str(exc), "het aantal openstaande voorstellen"),
                    ) from None
                # The SAME code that was just issued, read back through the
                # ONE public accessor (design 3.7): the letter the
                # channel shows and the letter the model reads must be the
                # same letter for the same proposal, and both come from this
                # one call - never a second allocation, never a guess.
                #
                # In its own fail-closed try: before this, `marker()` sat between `issue()`
                # above and the fail-closed `try/except` around
                # `code_presenter` below - outside both. Unreachable on the
                # real store today (nothing between `issue()` returning and
                # this line can have expired or redeemed the code it just
                # drew, in this same synchronous call), but the invariant a
                # few lines further down states in words - "a code nobody
                # saw must not be a code that still works" - is an absolute,
                # not "on the paths we thought of". Same repair as a failing
                # `code_presenter`: burn the code nobody has seen yet, then
                # refuse.
                try:
                    marker = confirmations.marker(code)
                except ConfirmError:
                    try:
                        confirmations.redeem(code, tool, clean, target_label, section=doelnaam)
                    except ConfirmError:
                        pass
                    raise ToolError(CHANNEL_FAILED) from None
                shown_target = _from_script(target_label)

                # THE code-free proposal, now as an Answer so it can leave
                # through `_rendered()` like every other outcome of this path.
                # Everything a human needs in order to decide is in it; the
                # code itself is not, because THIS text is what the model
                # reads (measured: the regression coverage below,
                # section 2.2 - a model that reads the code takes the second
                # step itself). `subject_is_name=False` throughout: every
                # subject here is this product's own vocabulary (the tool, the
                # argument names, "doel"), never an appliance object - the
                # object names sit in the OUTCOMES, and those the seam masks.
                # Built by a small factory instead of inline: two answers
                # share this exact shape and differ in nothing but the plan
                # text in the findings below - the MODEL's own answer
                # (`plan`, suppressed below 'volledig') and the operator's
                # own copy (`operator_plan`, never suppressed - see above).
                # Tool, doel, arguments, bevestigingscode and ongedaan maken
                # are identical in both and stay exactly as they already
                # were.
                # config_opslaan's own two findings, computed ONCE for both
                # copies of the proposal and appended after the fixed lines,
                # so no pinned prefix of this answer moves.
                eigen_bevindingen = _config_opslaan_voorstel_findings(doelnaam) if tool == "config_opslaan" else []
                # certificaat_vervangen's own: where the certificate it takes
                # off this virtual server is used as well. Same place, same
                # reason; nothing here reaches the code binding or the script.
                voorstel_namen: tuple[str, ...] = ()
                if tool == "certificaat_vervangen":
                    eigen_bevindingen, voorstel_namen = _vervangen_voorstel_findings(clean["dienst"], doelnaam)

                def _voorstel_answer(plan_voor_melding: str) -> Answer:
                    return Answer(
                        question=f"voorstel {tool}",
                        findings=[
                            Finding(
                                subject=tool,
                                outcome=f"VOORSTEL ({tool}), er is nog niets gewijzigd",
                                certainty=Certainty.ESTABLISHED,
                                # The plan is SCRIPT-authored and multi-line, so
                                # it does not sit in this field: it follows as one
                                # finding per line (`_script_notes`). In here it
                                # would put unprefixed foreign lines in the
                                # findings block - see there.
                                evidence="de controle vooraf (-WatIs) van het schrijfscript",
                                subject_is_name=False,
                            ),
                            *_script_notes(
                                "melding van de controle vooraf",
                                plan_voor_melding,
                                "letterlijk uit de controle vooraf (-WatIs) van het schrijfscript",
                            ),
                            # The target label is the OPERATOR's own label for the
                            # appliance, not an object on it - the same reading
                            # `status_ververs` makes when it stays outside the
                            # seam. It travels through `_from_script()` like any
                            # other free script text, so below 'volledig' this
                            # Finding's outcome is the seam's suppression text in
                            # the MODEL's own answer, not the label itself - the
                            # operator's own channel keeps the real label via
                            # `for_operator=True` at the `_present()` call below,
                            # same as it always did.
                            Finding(
                                subject="doel",
                                outcome=shown_target,
                                certainty=Certainty.ESTABLISHED,
                                evidence="het schrijfscript meldde dit doel zelf met [TARGET]",
                                subject_is_name=False,
                            ),
                            *[
                                Finding(
                                    subject=veld,
                                    outcome=clean[veld],
                                    certainty=Certainty.ESTABLISHED,
                                    evidence=("argument van deze aanroep, gecontroleerd tegen de allowlist"),
                                    subject_is_name=False,
                                )
                                for veld in sorted(clean)
                            ],
                            Finding(
                                subject="bevestigingscode",
                                outcome=(
                                    f"aan de beheerder getoond ({_channel_label}) - vraag de "
                                    "beheerder om de code en roep deze tool opnieuw aan met "
                                    "bevestiging=<code>"
                                ),
                                certainty=Certainty.ESTABLISHED,
                                evidence=(
                                    "De code is tien minuten geldig en werkt een keer, en staat niet in dit antwoord."
                                ),
                                subject_is_name=False,
                            ),
                            Finding(
                                subject="ongedaan maken",
                                outcome=_inverse_of(tool),
                                certainty=Certainty.ESTABLISHED,
                                evidence="vaste tekst van dit gereedschap",
                                subject_is_name=False,
                            ),
                            *eigen_bevindingen,
                        ],
                    )

                voorstel = _voorstel_answer(plan)
                # The operator's channel gets the REAL names: a human must see
                # what they are confirming. `clean` and `target_label` travel
                # unchanged. `operator_proposal` is the operator's OWN answer -
                # built from `operator_plan`, never the model's suppressed
                # `plan` - so its script-plan finding carries the real,
                # masked-not-suppressed text; `shown_target` below keeps the
                # seam's default suppression for the MODEL's own "doel"
                # Finding inside `voorstel`, while the operator's channel gets
                # the real, unsuppressed target via `for_operator=True`, same
                # as it already did. `_stamped()` on it, and not because this
                # text travels through the seam - it deliberately does not.
                # The administrator reads THIS text to decide, so it carries
                # the same two closing lines as everything else this path
                # says.
                operator_proposal = _stamped(_voorstel_answer(operator_plan)).to_text()
                await _present(
                    clean,
                    code,
                    target_label,
                    _from_script(target_label, for_operator=True),
                    operator_proposal,
                    marker,
                    doelnaam,
                )
                # caller_name=None, and provably so: every value in `clean`
                # passed the allowlist, and `_write_names()` collects exactly
                # that allowlist - so nothing here is a name the caller
                # invented and this server does not know.
                # `_with_marker()` AFTER `code_presenter(...)`, not before:
                # the channel already puts the marker in its own message,
                # so a proposal text that carried it too would
                # give the file channel two "voorstel "-lines - and both
                # this suite's own tests and the design insist on exactly one.
                return _with_marker(_rendered(doelnaam, voorstel, caller_name=None, extra_names=voorstel_namen), marker)

            if not target_label:
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        "De handeling is niet uitgevoerd: het schrijfscript meldde geen doel. "
                        "De bevestigingscode is niet ingewisseld.",
                        "het schrijfscript gaf geen [TARGET]-regel",
                    ),
                )
            audit.update(marker=_proposal_marker())
            try:
                confirmations.redeem(bevestiging, tool, clean, target_label, section=doelnaam)
            except ConfirmError as exc:
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(tool, str(exc), "de bevestigingscode is getoetst aan het voorstel"),
                ) from None
            # The channel may hold a copy of the code (the file channel
            # does). It is spent now, so blank it now - the file channel only
            # while it still shows this code, not a newer one - best effort: the
            # action is authorized at this point, and a file that cannot be
            # rewritten must not turn a redeemed handling into a crash.
            mark_spent = getattr(code_presenter, "spent", None)
            if mark_spent is not None:
                try:
                    mark_spent(bevestiging)
                except Exception:  # noqa: BLE001 - never fatal after a redeem
                    pass
            # THE REAL RUN, as a future of its own and awaited through a
            # shield. From here the write is out of this coroutine's hands:
            # the script runs in a worker thread that cannot be called back,
            # so a cancellation may not pretend otherwise. The shield keeps
            # the run itself out of the cancellation, `write_worker` hands it
            # to the gate (which then waits for the worker instead of for
            # this task), and `_report_orphan` puts its outcome
            # where an operator can still find it.
            # WHO confirmed. `venster` and `bestand` cannot name anyone -
            # `getattr` with a default (the same idiom as
            # `_channel_label`/`mark_spent` above) keeps that a safe,
            # uniform question to ask of either. `sso` CAN, but not through
            # a bare attribute read: ONE `SsoCodeChannel` instance lives for
            # the server's whole life, and multiple outstanding proposals
            # are an acknowledged scenario (an older, un-redeemed code stays
            # valid for TTL_S - docs/klant/SECURITY.md), so a bare
            # `.bevestiger` would answer for whichever proposal ran LAST,
            # not for `bevestiging` - the code THIS call is redeeming.
            # `bevestiger_for(bevestiging)` asks
            # for the confirmer bound to that specific code instead, when
            # the channel offers it; `venster` and `bestand` do not, so they
            # fall back to the same honest `None` they always had. It is not
            # read a second time from `result` below - `perform()` only
            # carries this value through, it never learns it from the
            # script - so the local variable IS the answer.
            # ... and the bare attribute is not read as a FALLBACK either:
            # the paragraph above forbids it in words,
            # and leaving it in place here meant a FUTURE channel of exactly
            # that shape would still have had its un-code-bound confirmer
            # printed in `onderhoud_backup_maken`'s answer below. The honest
            # `None` - what `venster` and `bestand` already yield - is the
            # fallback. Closed on BOTH write paths now, the same as the
            # phase tool's own copy.
            bevestiger_for = getattr(code_presenter, "bevestiger_for", None)
            bevestiger = bevestiger_for(bevestiging) if bevestiger_for is not None else None
            audit.update(bevestiger=bevestiger)
            audit.update(outcome="onbekend")
            worker = asyncio.ensure_future(asyncio.to_thread(_run_write, False, bevestiger))
            write_worker.append(worker)
            try:
                result = await asyncio.shield(worker)
            except asyncio.CancelledError:
                worker.add_done_callback(
                    lambda finished: _report_orphan(
                        finished,
                        doelnaam=doelnaam,
                        target_label=target_label,
                        bevestiger=bevestiger,
                        context_values=context_values,
                    )
                )
                raise
            except Exception as exc:
                # 1.1: a TYPED start failure proves the script did not start
                # (it comes from before any child existed): the honest
                # "niet gestart", not "gestart maar de uitkomst is NIET
                # vastgesteld". Every other error keeps that sentence.
                not_started = _not_started_sentence(exc) if isinstance(exc, ProcessNotStarted) else None
                if not_started is not None:
                    audit.update(outcome="mislukt", oorzaak=_not_started_cause(exc))
                    raise _failure(
                        doelnaam,
                        f"uitvoering {tool}",
                        _note(
                            tool,
                            EXPORTDOEL_NA_INWISSELEN_TEXT.format(
                                reden=SCRIPT_NIET_GESTART_REDEN.format(soort=not_started)
                            ),
                            SCRIPT_NIET_GESTART_EVIDENCE + ", na het inwisselen van de code",
                        ),
                    ) from None
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        "De handeling is gestart maar de uitkomst is NIET vastgesteld "
                        f"({type(exc).__name__}). De bevestigingscode is verbruikt. Controleer "
                        "de appliance voordat je opnieuw probeert.",
                        "de uitvoering wierp een fout op in plaats van een uitkomst te melden",
                        # The ONE branch of this path where nothing was read:
                        # the run threw, so the write outcome - the field that
                        # carries the verdict here - never reached this layer.
                        # The other failure branches keep ESTABLISHED: there
                        # the script spoke and this layer read what it said.
                        certainty=Certainty.NOT_ESTABLISHED,
                        reason=(
                            "het schrijfscript meldde geen uitkomst; deze laag heeft niets gelezen om over te oordelen"
                        ),
                    ),
                ) from None
            audit.update(
                outcome="geslaagd" if result.ok else "mislukt",
                target=_from_script(result.target) if result.target else None,
                action_id=result.actie_id,
            )
            if not result.ok:
                register_warning = _write_action_register(
                    onderhoud,
                    tool=tool,
                    doel=doelnaam,
                    actieid=result.actie_id,
                    uitkomst="mislukt",
                    bevestiger=bevestiger,
                    objectnaam=result.object_name,
                )
                # Findings where there used to be three lines in one string:
                # this is the branch that prints the most appliance text, and
                # a finding per statement is what the seam masks per
                # statement. The script's own output is one finding per LINE
                # (`_script_notes`), so no line of it can pose as a finding
                # line or as a verdict marker of this product.
                if register_warning is not None:
                    raise _failure(
                        doelnaam,
                        f"uitvoering {tool}",
                        _note(
                            "actieregister",
                            register_warning.outcome,
                            register_warning.evidence,
                            certainty=register_warning.certainty,
                            reason=register_warning.reason,
                        ),
                    )
                raise _failure(
                    doelnaam,
                    f"uitvoering {tool}",
                    _note(
                        tool,
                        f"handeling MISLUKT: {_from_script(result.eindstatus, extra_values=context_values)}",
                        "de regel [EINDSTATUS] van het schrijfscript",
                    ),
                    *_script_notes(
                        "uitvoer van het schrijfscript",
                        _from_script(result.text.rstrip(), extra_values=context_values),
                        "letterlijk uit de uitvoer van het schrijfscript",
                    ),
                    _note(
                        "bevestigingscode",
                        "verbruikt",
                        "een code werkt een keer, ook als de handeling mislukt",
                    ),
                )
            if tool == "onderhoud_backup_maken":
                # The exit code alone (`result.ok` above) is not proof for
                # THIS tool: design 2.3 requires the read-back to find
                # the object again on the COLLECTION, never a GET on the
                # name (a removed object answered a GET-by-name with 599, not
                # 404, on the lab - lab lesson `nitro-readback-599-vs-404`).
                # The name checked here is `result.object_name`
                # - the name THIS CALL commanded the script to use, read by
                # `perform()` from the argument list it built and carried
                # onto the result - never the device's `[TARGET]` label. A
                # prior version compared the device label as a substring of
                # the read-back detail and a stale object from an earlier run
                # passed, because the device label sits inside every backup
                # name that target ever formed (design's own name grammar
                # guarantees it). `[TARGET]` keeps exactly one meaning here:
                # `handelen._marker()`'s first occurrence, the same one
                # `result.target` already is.
                gevonden, detail = readback_ok(result.text, result.object_name)
                if not gevonden:
                    audit.update(outcome="mislukt")
                    register_warning = _write_action_register(
                        onderhoud,
                        tool=tool,
                        doel=doelnaam,
                        actieid=result.actie_id,
                        uitkomst="mislukt",
                        bevestiger=bevestiger,
                        objectnaam=result.object_name,
                    )
                    if register_warning is not None:
                        raise _failure(
                            doelnaam,
                            f"uitvoering {tool}",
                            _note(
                                "actieregister",
                                register_warning.outcome,
                                register_warning.evidence,
                                certainty=register_warning.certainty,
                                reason=register_warning.reason,
                            ),
                        )
                    raise _failure(
                        doelnaam,
                        f"uitvoering {tool}",
                        _note(
                            tool,
                            f"handeling MISLUKT: {_from_script(detail)}",
                            "de teruglezing op de collectie config/systembackup",
                        ),
                        _note(
                            "bevestigingscode",
                            "verbruikt",
                            "een code werkt een keer, ook als de handeling mislukt",
                        ),
                    )
            # config_opslaan: exit code 0 is not proof either. Unlike the other
            # tools, the READ-BACK is judged here, not by the script: the save
            # script prints the raw `show ns config` it read right after
            # `save ns config`, and `save_readback_ok()` decides - fail-closed
            # on every shape it does not know. A failed read-back is a FAILED
            # action with a spent code, the same route as the backup above.
            eigen_teruglezing: list[Finding] = []
            if tool == "config_opslaan":
                opgeslagen, oordeel = save_readback_ok(result.text)
                if not opgeslagen:
                    audit.update(outcome="mislukt")
                    register_warning = _write_action_register(
                        onderhoud,
                        tool=tool,
                        doel=doelnaam,
                        actieid=result.actie_id,
                        uitkomst="mislukt",
                        bevestiger=bevestiger,
                        objectnaam=result.object_name,
                    )
                    raise _failure(
                        doelnaam,
                        f"uitvoering {tool}",
                        _note(
                            tool,
                            f"handeling MISLUKT: {oordeel}",
                            f"de teruglezing: {CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE}",
                        ),
                        *([register_warning] if register_warning is not None else []),
                        _note(
                            "bevestigingscode",
                            "verbruikt",
                            "een code werkt een keer, ook als de handeling mislukt",
                        ),
                    )
                eigen_teruglezing = [
                    Finding(
                        subject="teruglezing",
                        outcome=oordeel,
                        certainty=Certainty.ESTABLISHED,
                        evidence=CONFIG_OPSLAAN_TERUGLEZING_EVIDENCE,
                        subject_is_name=False,
                    )
                ]
            # This layer never composes the word "teruggelezen" itself -
            # that claim belongs to the
            # write script, which does the actual read-back against the
            # appliance. Below: only lines the script's OWN stdout carries
            # (and only when there are any), and the script's own
            # [EINDSTATUS] marker shown verbatim as the status - never a
            # product-invented summary of what happened.
            # The action register (design 3.5): this is the moment the action is
            # ESTABLISHED as executed - exit code read, and for a backup the
            # object read back on the collection - so this is where the row is
            # written. A proposal never reaches this line.
            register_warning = _write_action_register(
                onderhoud,
                tool=tool,
                doel=doelnaam,
                actieid=result.actie_id,
                uitkomst="geslaagd",
                bevestiger=bevestiger,
                objectnaam=result.object_name,
                doel_vastgesteld=result.target == target_label,
            )
            readback = _from_script(
                "\n".join(
                    regel
                    for regel in result.text.splitlines()
                    if "teruggelezen" in regel and not regel.startswith("[EINDSTATUS]")
                ),
                extra_values=context_values,
            )
            waarschuwing = []
            if result.target != target_label:
                waarschuwing = [
                    Finding(
                        subject="doel",
                        outcome=(
                            f"LET OP: doel na uitvoering ({_from_script(result.target)}) wijkt af "
                            f"van het voorstel ({_from_script(target_label)})"
                        ),
                        certainty=Certainty.ESTABLISHED,
                        evidence="het schrijfscript meldde [TARGET] voor en na de uitvoering",
                        subject_is_name=False,
                    )
                ]
            # The read-back, only when the script itself printed one, and
            # under a subject that does not contain the word: this layer never
            # composes the claim "teruggelezen" on its own authority. Script
            # authored and multi-line, so one finding per line for the same
            # reason as the failure branch below - see `_script_notes()`. The
            # `if readback` guard stays: an ABSENT read-back is silence here,
            # not a statement, and that rule predates this repair.
            melding = (
                _script_notes(
                    "melding van het schrijfscript",
                    readback,
                    "letterlijk uit de uitvoer van het schrijfscript",
                )
                if readback
                else []
            )
            uitvoering = Answer(
                question=f"uitvoering {tool}",
                findings=[
                    *waarschuwing,
                    Finding(
                        subject=tool,
                        outcome=f"UITGEVOERD ({tool})",
                        certainty=Certainty.ESTABLISHED,
                        # The actie-id is script-reported free text too -
                        # through the same seam as the target, the plan and
                        # the eindstatus, so it is suppressed below
                        # 'volledig' exactly like they are. The local action
                        # register above (`_write_action_register`) already
                        # holds the real actie-id; this is only the text the
                        # model reads.
                        evidence=(f"actie-id {_from_script(result.actie_id)}, doel {_from_script(result.target)}"),
                        subject_is_name=False,
                    ),
                    *eigen_teruglezing,
                    *melding,
                    *([register_warning] if register_warning is not None else []),
                    Finding(
                        subject="eindstatus",
                        outcome=_from_script(result.eindstatus, extra_values=context_values),
                        certainty=Certainty.ESTABLISHED,
                        evidence="de regel [EINDSTATUS] van het schrijfscript",
                        subject_is_name=False,
                    ),
                    Finding(
                        subject="ongedaan maken",
                        outcome=_inverse_of(tool),
                        certainty=Certainty.ESTABLISHED,
                        evidence="vaste tekst van dit gereedschap",
                        subject_is_name=False,
                    ),
                    # The first gate (design 3.4): the confirmer, in the
                    # answer, even when the value is None - and then it says
                    # so with a reason instead of leaving the line out. Only
                    # for onderhoud_backup_maken; the other four
                    # writing tools are unchanged. The outcome is the VALUE
                    # only - `_bevestiger_regel()` no longer prepends the
                    # word, which used to double it against this Finding's
                    # own subject prefix; the line is
                    # pinned in tests/test_product_surface.py.
                    *(
                        [
                            Finding(
                                subject="bevestiger",
                                outcome=_bevestiger_regel(bevestiger),
                                certainty=Certainty.ESTABLISHED,
                                evidence=(
                                    "wat het codekanaal over de bevestiger kon zeggen bij het inwisselen van de code"
                                ),
                                subject_is_name=False,
                            )
                        ]
                        if tool == "onderhoud_backup_maken"
                        else []
                    ),
                ],
            )
            # Only a run that really succeeded makes the reading answers
            # stale. A failed handling changed nothing to count.
            writes_since_scan.record_write()
            # caller_name=None for the same reason as on the proposal path:
            # what ran was `clean`, and every value in it is on the allowlist
            # that `_write_names()` collects.
            return _rendered(doelnaam, uitvoering, caller_name=None)

        async def gated_work():
            """`work()`, but the EXECUTION branch behind the single-writer
            gate (see `_writer_gate` above).

            The whole branch, deliberately - preview, redeem AND run. The
            preview establishes the target the code is bound to, so a second
            caller that previewed while the first was still writing would
            bind its code to a target that is already being changed.
            Proposals are not gated: they run the script with -WatIs, change
            nothing, and are exactly the call an operator makes while looking
            at the previous one.

            OUTSIDE the gate on purpose: `_decide()` (in `_guarded_async`
            below), so a caller who may not act at all is refused without
            ever taking a place in the queue.
            """
            if not bevestiging.strip():
                return await work()
            async with _writer_gate(write_worker):
                return await work()

        async def logged_work():
            try:
                return await gated_work()
            finally:
                if audit:
                    _action_log(tool=tool, client=caller[0], **audit)

        return await _guarded_async(
            ctx,
            logged_work,
            tool,
            {**stripped, "bevestiging": bool(bevestiging.strip())},
            client_slot=caller,
        )

    def _inverse_of(tool: str) -> str:
        return {
            "certificaat_klaarzetten": (
                "Ongedaan maken: deze tool ruimt een klaargezet certificaat niet zelf op; "
                "verwijderen is een aparte beheerstap buiten deze handeling."
            ),
            "certificaat_vervangen": "Ongedaan maken kan met certificaat_vervangen met het vorige certificaat als nieuwcert.",
            "dienst_lid_uitschakelen": "Ongedaan maken kan met dienst_lid_inschakelen met dezelfde dienst en hetzelfde lid.",
            "dienst_lid_inschakelen": "Ongedaan maken kan met dienst_lid_uitschakelen met dezelfde dienst en hetzelfde lid.",
            "onderhoud_backup_maken": (
                "Ongedaan maken: een backup heeft geen inverse. Het object blijft staan; het is "
                "een terugrolpunt en geen wijziging. Verwijderen is een aparte beheerstap buiten "
                "deze handeling."
            ),
            "config_opslaan": CONFIG_OPSLAAN_INVERSE_TEXT,
        }[tool]

    # The disclosure gate that used to demand 'volledig' is gone, and the
    # reason it existed with it: `_act()` composed its own text and never
    # passed through `render()`, and `handelen.validate()` named the whole
    # allowlist when it refused. Both are repaired - a refusal carries
    # only a reason code plus what the caller supplied itself, and every
    # outcome of the writing path that can carry appliance text leaves
    # through `render()`: the proposal, the execution, the refusal AND every
    # failure branch (`_failure()` in `_act()`). Two ToolErrors stay outside
    # it on purpose, and neither can name anything off the appliance: the
    # empty-allowlist refusal in `_target_for()` and `CHANNEL_FAILED`, both
    # this product's own frozen sentences. What remains is the seam, and the
    # seam works: at 'beperkt' a caller hands in pseudonyms and gets
    # pseudonyms back.
    writing_allowed = action_script is not None and fixture_dir is not None
    if writing_allowed and disclosure is Disclosure.MINIMAL:
        # 'minimaal' is not a leak, it is a MISFIT. That rendering replaces
        # the findings of an answer with counts (`disclosure._minimal`), so a
        # proposal loses its VOORSTEL line, its arguments and the line that
        # tells the caller to ask the administrator for the code - while a
        # code is issued and shown to that administrator all the same. The
        # second step of every writing tool is then unreachable, exactly as
        # it is without a channel below. start.py refuses this combination
        # outright; here the seven are dropped, because a library call cannot
        # exit the process.
        writing_allowed = False
        print(
            "Let op: handelen is ingesteld met openheid minimaal. Die weergave vat een "
            "antwoord samen tot tellingen en kan een voorstel niet dragen: de aanwijzing om "
            "opnieuw aan te roepen met de bevestigingscode verdwijnt, terwijl die code wel "
            "aan de beheerder getoond wordt. De schrijvende gereedschappen worden niet "
            "aangemeld; kies openheid beperkt of volledig.",
            file=sys.stderr,
        )
    if writing_allowed and code_presenter is None:
        # Fail closed, the same shape as the disclosure gate below: without a
        # channel the confirmation code reaches nobody, so the second step of
        # every writing tool is unreachable. Offering tools that can only
        # refuse is the 'half a configuration' start.py rejects outright; a
        # library caller cannot be exited, so the seven are dropped and the
        # reason goes to stderr.
        writing_allowed = False
        print(
            "Let op: handelen is ingesteld zonder codekanaal. De bevestigingscode kan dan "
            "aan niemand getoond worden en de tweede stap is onbereikbaar; de schrijvende "
            "gereedschappen worden niet aangemeld.",
            file=sys.stderr,
        )
    if writing_allowed:
        if "certificaat" in chapters:

            @server.tool()
            async def certificaat_klaarzetten(
                certnaam: str, bevestiging: str = "", doel: str = "", *, ctx: Context
            ) -> str:
                """Hoofdstuk certificaat. Zet een vervangend certificaat klaar op de appliance zonder het te binden. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit als er een nieuw certificaat klaargezet moet worden."""
                return await _act(ctx, "certificaat_klaarzetten", {"certnaam": certnaam, "doel": doel}, bevestiging)

            @server.tool()
            async def certificaat_vervangen(
                dienst: str, nieuwcert: str, bevestiging: str = "", doel: str = "", *, ctx: Context
            ) -> str:
                """Hoofdstuk certificaat. Wisselt op een dienst het gebonden certificaat om naar een ander; het schrijfscript leest terug en het product geeft die uitkomst letterlijk door. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit als een certificaat vervangen moet worden."""
                return await _act(
                    ctx,
                    "certificaat_vervangen",
                    {"dienst": dienst, "nieuwcert": nieuwcert, "doel": doel},
                    bevestiging,
                )

        if "dienst" in chapters:

            @server.tool()
            async def dienst_lid_uitschakelen(
                dienst: str, lid: str, bevestiging: str = "", doel: str = "", *, ctx: Context
            ) -> str:
                """Hoofdstuk dienst. Haalt een lid uit een servicegroup (OUT OF SERVICE); het schrijfscript leest terug en het product geeft die uitkomst letterlijk door. Het argument dienst is hier de servicegroup - de naam die dienst_status onder 'servicegroup' toont - niet de virtuele server. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit als een webserver uit de dienst moet."""
                return await _act(
                    ctx,
                    "dienst_lid_uitschakelen",
                    {"dienst": dienst, "lid": lid, "doel": doel},
                    bevestiging,
                )

            @server.tool()
            async def dienst_lid_inschakelen(
                dienst: str, lid: str, bevestiging: str = "", doel: str = "", *, ctx: Context
            ) -> str:
                """Hoofdstuk dienst. Zet een eerder uitgeschakeld lid weer in de servicegroup; het schrijfscript leest terug en het product geeft die uitkomst letterlijk door. Het argument dienst is hier de servicegroup - de naam die dienst_status onder 'servicegroup' toont - niet de virtuele server. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit om een uitschakeling ongedaan te maken."""
                return await _act(
                    ctx,
                    "dienst_lid_inschakelen",
                    {"dienst": dienst, "lid": lid, "doel": doel},
                    bevestiging,
                )

    if writing_allowed and "onderhoud" in chapters and onderhoud is not None:

        @server.tool()
        async def onderhoud_backup_maken(bevestiging: str = "", doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk onderhoud. Laat de NetScaler zelf een volledige backup maken en leest die terug in de backupcollectie; de naam wordt hier gevormd in UTC. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit voordat er aan de NetScaler gewerkt wordt."""
            return await _act(ctx, "onderhoud_backup_maken", {"doel": doel}, bevestiging)

    # `onderhoud_upgrade_fase` registers only when a target may actually run
    # it (profielregel, ontwerp 3.1) - `onderhoud` without any such target in
    # `handelen.toegestaan` is NOT a start error (start.py's own seventh
    # row): the tool simply does not appear, exactly like every other
    # profile gate in this file (the chapters set above, `writing_allowed`
    # itself).
    if (
        writing_allowed
        and "onderhoud" in chapters
        and onderhoud is not None
        and any(allowlist.allows(naam, "onderhoud_upgrade_fase") for naam in allowlist.targets())
    ):

        @server.tool()
        async def onderhoud_upgrade_fase(
            fase: str,
            run: str = "",
            snapshotverwijzing: str = "",
            doelbuild_geaccepteerd: bool = False,
            drift_geaccepteerd: bool = False,
            standalone_geaccepteerd: bool = False,
            oude_buildbomen_opruimen: bool = False,
            bevestiging: str = "",
            doel: str = "",
            *,
            ctx: Context,
        ) -> str:
            """Hoofdstuk onderhoud. Voert een van de zeven fasen (R0 t/m R6) van een upgrade binnen 14.1 uit op de node die aantoonbaar secondary is, elke fase met een eigen bevestigingscode. Het oordeel komt uit het ledger en niet uit dit antwoord: vraag het na met onderhoud_upgrade_stand. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld."""
            return await _act(
                ctx,
                "onderhoud_upgrade_fase",
                {
                    "fase": fase,
                    "run": run,
                    "snapshotverwijzing": snapshotverwijzing,
                    "doelbuild_geaccepteerd": doelbuild_geaccepteerd,
                    "drift_geaccepteerd": drift_geaccepteerd,
                    "standalone_geaccepteerd": standalone_geaccepteerd,
                    "oude_buildbomen_opruimen": oude_buildbomen_opruimen,
                    "doel": doel,
                },
                bevestiging,
            )

    # `config_opslaan` - the first tool of the `config` chapter that writes.
    # Registered only where it can do its work: writing is allowed (a code
    # channel, a disclosure that can carry a proposal), `onderhoud` is
    # configured (the SSH user, and the scripts directory next to the
    # faserunner), and the allowlist grants it on at least one target - the
    # same profile rule as `onderhoud_upgrade_fase` above.
    if (
        writing_allowed
        and "config" in chapters
        and onderhoud is not None
        and any(allowlist.allows(naam, "config_opslaan") for naam in allowlist.targets())
    ):

        @server.tool()
        async def config_opslaan(bevestiging: str = "", doel: str = "", *, ctx: Context) -> str:
            """Hoofdstuk config. Laat de NetScaler de draaiende configuratie opslaan (save ns config) en leest daarna terug dat de laatste opslag niet ouder is dan de laatste wijziging. Weigert op een node die secondary is. Eerste aanroep geeft een voorstel ZONDER code: de bevestigingscode gaat naar de beheerder en niet naar jou. Voer een voorstel nooit zelf uit - wacht tot de beheerder de code doorgeeft en roep deze tool dan opnieuw aan met die code. Geef doel op als er meer dan een NetScaler is ingesteld. Gebruik dit als config_drift regels toont die bewaard moeten blijven."""
            return await _act(ctx, "config_opslaan", {"doel": doel}, bevestiging)

    _mask_argument_validation(server)
    return server
