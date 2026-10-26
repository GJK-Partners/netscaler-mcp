"""The four actions of the demo, as a thin edge around the reviewed
PowerShell write tool (`film\\Invoke-GjkLabWrite.ps1` in the demo repo).

Why a wrapper and not a Python NITRO client: that script has been hardened
through external review and carries the guardrails this product would
otherwise have to rebuild - object allowlist, name grammar, fingerprint
pin, ownership register, compensation in reverse order, and a read-back
after every change. For the demo the product does not reimplement that
path; it starts it as a separate process, exactly as scanning starts the
collector. What lives HERE is the edge: which objects this product may
name at all, how the argument list is built, that a preview always carries
-WatIs, and how the script's output is read - never the writing itself.

CONTRACT this product depends on but cannot enforce - the script lives in
another repository, so this states the requirement and names what measures
a violation, never what proves compliance. At `onderhoud_backup_maken`
specifically: this side forms a time-stamped `-BackupNaam` itself
(`backup_name()` in `backup.py`), but the script's own `[TARGET]` line -
read on the preview AND the real run, see `perform()` below and
`mcp_server._act()`, which binds the confirmation code to it - must stay
IDENTICAL across the WHOLE attempt, not only across `-WatIs` calls: the
proposal preview, the fresh re-check preview `_act()` runs right before
redeeming the code, AND the real, non-preview run that follows a
successful redeem. It is the operator's label for the appliance, never the
name of the object being made, so it must carry no name and no timestamp
that differs per invocation. A script that echoes its own time-stamped
object name back as `[TARGET]` drifts in one of two places, with two
different consequences. Drift between the two previews burns the
confirmation code (the redeem is refused as a mismatch) and fails every
backup structurally, one consumed code at a time -
`tests/test_handelen_zonder_code.py`'s
`test_CONTRACT_a_backup_target_label_that_drifts_per_invocation_burns_the_code_unused`
measures that CONSEQUENCE with a stub script. Drift between the
confirm-time preview and the real run is caught too late to refuse - the
write already ran by the time `_act()` reads `result.target` - so it
surfaces instead as a `LET OP: doel na uitvoering ... wijkt af van het
voorstel` finding on an otherwise successful answer (`mcp_server.py`'s
`if result.target != target_label` check); the same file's
`test_a_target_label_that_drifts_only_on_the_real_run_gets_a_LET_OP_not_a_refusal`
measures that branch. The other half of the same contract: the script must
print a line that (case-insensitively, after whitespace) starts `[OK]`
directly followed by `teruggelezen op de collectie config/systembackup:`
and a non-empty detail; the same phrase behind another marker, or with
`ontbreekt`/`niet gevonden` in the line (any case or spacing), never
counts, and a `[FOUT]` line that names the object fails the whole
read-back even next to an `[OK]` line - this
product READS that line (`backup.py`'s `_READBACK` expression) and never
composes the word "teruggelezen" itself. What actually decides pass or
fail is narrower than that shape suggests: `readback_ok()` requires the
exact `-BackupNaam` this side formed (`result.object_name`) to appear
literally INSIDE that detail (`naam in detail`, `backup.py`) - the `.tgz`
extension, the size, the timestamp and the trailing `, ...` are
illustrative, not required. The lab-evidence round on the real script is
what still has to verify the real script honours both halves.

The allowlist itself is NOT in this file: what an administrator allows is a
fact about one installation, so the VALUES come from the configuration
(`handelen.toegestaan`, read by start.py) and reach `validate()` as an
`Allowlist` argument. What stays in code is the SHAPE - which tools exist,
which arguments each takes, which of them form their own object - plus the
denylist, which an allowlist may never release.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from nsmcp.answer import Answer, Certainty, Finding
from nsmcp.backup import BACKUP_LEVEL, backup_name
from nsmcp.collect import _stop_child_process
from nsmcp.powershell import (
    ChildWorkingDirectoryUnusable,
    PowerShellMissing,
    ScriptPinMismatch,
    check_script_pins,
    child_working_directory,
    powershell_path,
    script_policy,
    start_powershell,
)
from nsmcp.upgrade import is_safe_run_name, runner_current_build, runner_floor, runner_package
from nsmcp.upgrade_plan import PHASE_NAMES

# The writing tools (design 2.8), seven with `config_opslaan`. The list is
# EXHAUSTIVE and lives here rather than in mcp_server.py because start.py needs
# it without building a server: it validates the allowlist against this list.
# tests/test_no_network.py defines a READING tool as a registered tool that is
# NOT in here.
WRITE_TOOLS: tuple[str, ...] = (
    "certificaat_klaarzetten",
    "certificaat_vervangen",
    "config_opslaan",
    "dienst_lid_inschakelen",
    "dienst_lid_uitschakelen",
    "onderhoud_backup_maken",
    "onderhoud_upgrade_fase",
)

# The tools that FORM THEIR OWN OBJECT out of data the caller does not supply
# - a backup name built from the target and the UTC clock, a phase the runner
# names itself, the running configuration of the target as a whole. Only
# these may use the objectless allowlist form (`true` / `false` per target).
# A tool that takes its object name from a tool ARGUMENT must use the object
# form, or the allowlist would stop bounding what it may touch (design 2.8,
# 3.2).
OBJECTLESS_TOOLS: tuple[str, ...] = ("onderhoud_backup_maken", "onderhoud_upgrade_fase", "config_opslaan")

# Which arguments each tool takes. This was implicit in ALLOWED (the keys of
# the per-tool dict); now that the VALUES come from the configuration the
# SHAPE has to stay in code - otherwise a configuration could invent an
# argument this product never passes on to the write script.
ARGUMENTS: dict[str, tuple[str, ...]] = {
    "certificaat_klaarzetten": ("certnaam",),
    "certificaat_vervangen": ("dienst", "nieuwcert"),
    "dienst_lid_uitschakelen": ("dienst", "lid"),
    "dienst_lid_inschakelen": ("dienst", "lid"),
    "onderhoud_backup_maken": (),
    # Saves the whole running configuration of the target: no object, no
    # argument.
    "config_opslaan": (),
    # Not appliance object names (design 3.1: this tool names no object a
    # caller supplies) - so `validate()`'s objectless branch never inspects
    # their VALUES, only that no argument outside this set was sent. Their
    # values are checked on FORM by `validate_phase_arguments()` below, not
    # against an allowlist.
    "onderhoud_upgrade_fase": (
        "fase",
        "run",
        "snapshotverwijzing",
        "doelbuild_geaccepteerd",
        "drift_geaccepteerd",
        "oude_buildbomen_opruimen",
        "standalone_geaccepteerd",
    ),
}


@dataclass(frozen=True)
class Allowlist:
    """What the ADMINISTRATOR allows, per target, per tool.

    Two forms, both from the configuration file and never from a tool
    argument (design 3.2):

    - the OBJECT form - `{"<argument>": ("<value>", ...)}` - for a tool whose
      object the caller names;
    - the OBJECTLESS form - `True` / `False` - for a tool in
      `OBJECTLESS_TOOLS`, which forms its own object.

    Absent, `False` and an empty tuple all mean the same thing: not allowed.
    Three spellings of one refusal, deliberately - an operator who removes the
    last value must not accidentally write a wildcard.
    """

    per_target: dict

    def targets(self) -> tuple[str, ...]:
        return tuple(sorted(self.per_target))

    def entry(self, target: str, tool: str):
        section = self.per_target.get(target)
        if not isinstance(section, dict):
            return None
        return section.get(tool)

    def allows(self, target: str, tool: str) -> bool:
        """Is this tool allowed on this target AT ALL - without judging the
        arguments a caller typed. Nothing consumes it yet; it exists for the
        reading half of the product, which will have to say whether an
        operator has any writing room here before it advises anything. Never
        a substitute for validate().

        It answers a SECURITY question, so it may not say yes where the
        truth is "nothing is permitted". That is why the object form is
        measured against the whole `ARGUMENTS[tool]` key set and not against
        the keys the entry happens to carry: validate() looks up every
        argument of the tool, and one that is missing resolves to an empty
        tuple - which refuses every call. An incomplete entry is a no, not a
        partial yes.
        """
        entry = self.entry(target, tool)
        if entry is True:
            return True
        if isinstance(entry, dict):
            fields = ARGUMENTS.get(tool, ())
            return bool(fields) and all(bool(entry.get(field)) for field in fields)
        return False


# The port of the demo members. Fixed for the demo.
MEMBER_PORT = "3389"

DENIED_PREFIXES = ("nshttps-", "nsrpcs-")
DENIED_NAMES = ("ns-server-certificate", "ns-sftrust-certificate")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,62}")
_TIMEOUT_S = 300
# How long the write script gets, after the polite stop, to run its own
# `finally` block (compensation in reverse order plus a read-back) and flush
# what it printed. The same order of magnitude as the grace period
# `collect._stop_child_process` uses for the collector.
_GRACE_S = 5.0


class ActionError(Exception):
    """This action is not allowed or could not be described. Never silent."""


class ProcessNotStarted(ActionError):
    """1.1: a child process of this product did NOT start, and that is
    PROVEN on the path that raises this: the failure came before `Popen`
    returned a child (or `Popen` failed on every attempt). A caller may
    therefore treat it as "no child exists" and release what it reserved.

    No free text: the message is the fixed `soort` only. The underlying
    error goes along as its CLASS NAME (`oorzaak`), for the action log -
    never its text, which carries local paths (the runner, its log file,
    the PowerShell install path). MEASURED before (1.0.3): all three start
    failures of the detached runner were one `ActionError` with `str(exc)`
    in it, and the answer named the wrong cause for an unusable working
    directory. The answer sentence belongs to the caller
    (`mcp_server._not_started_sentence`), mapped on the TYPE."""

    soort = "proces"

    def __init__(self, cause: BaseException | type[BaseException] | None = None) -> None:
        if cause is None:
            self.oorzaak: str | None = None
        else:
            self.oorzaak = (cause if isinstance(cause, type) else type(cause)).__name__
        super().__init__(self.soort)


class RunnerWorkdirUnusable(ProcessNotStarted):
    """The fixed working directory for child processes is not usable
    (`powershell.ChildWorkingDirectoryUnusable`), before any `Popen`."""

    soort = "werkmap"


class RunnerLogUnopenable(ProcessNotStarted):
    """The log file next to the ledger did not open, before any `Popen`."""

    soort = "logbestand"


class RunnerProcessNotStarted(ProcessNotStarted):
    """`Popen` itself failed, on every attempt it got."""

    soort = "proces"


class ScriptPinRefused(ProcessNotStarted):
    """A script did not match its pin (`powershell.ScriptPinMismatch`), so
    nothing was started: the script-runner route (`typed_runner`) and the
    `-WatIs` preview of the faserunner."""

    soort = "scriptpin"


class PowerShellNotFound(ProcessNotStarted):
    """Windows PowerShell is not where Windows says it is
    (`powershell.PowerShellMissing`): the script-runner route
    (`typed_runner`) and the `-WatIs` preview of the faserunner."""

    soort = "powershell"


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    preview: bool
    actie_id: str | None
    target: str | None
    eindstatus: str
    text: str
    # WHO confirmed, when the code channel can say (design 3.4, C5). None is
    # the honest value for the `venster` and `bestand` kinds: they show a code
    # to whoever is at the screen and cannot name that person. The `sso`
    # kind can - and the runner REFUSES a channel that cannot.
    bevestiger: str | None = None
    # The name this side commanded the write script to use,
    # for a tool that forms its own object (`onderhoud_backup_maken` today -
    # design 3.2). Read from the SAME argument list `perform()` builds and
    # hands to the script (`_argument_value`), never asked of the script a
    # second time and never parsed back out of its output - the clock runs
    # ONCE, in `build_arguments()`, and this field carries what it produced.
    # None for every tool that does not form its own object.
    object_name: str | None = None


# The two tools whose `dienst` argument is the SERVICEGROUP, not the virtual
# server. The parameter name is the same word in both halves of the product
# (the design keeps it that way), but the reading tool `dienst_status` asks
# for the virtual server under it and these two ask for the servicegroup that
# hangs off it. A caller who hands the virtual server here otherwise gets a
# bare "not on the allowlist" and no way to know which of the two names was
# expected.
_SERVICEGROUP_TOOLS = ("dienst_lid_uitschakelen", "dienst_lid_inschakelen")
_SERVICEGROUP_HINT = (
    "; let op: 'dienst' is hier de servicegroup - de naam die dienst_status onder "
    '"servicegroup" toont - en niet de virtuele server'
)


def _which_dienst(tool: str, field: str) -> str:
    return _SERVICEGROUP_HINT if field == "dienst" and tool in _SERVICEGROUP_TOOLS else ""


# The reason codes a refusal may carry. A CODE, not a sentence, so a caller
# (and a test) can act on the reason without matching on Dutch text - and so
# the sentence can be written once, here, with nothing in it but what the
# caller itself supplied.
REFUSAL_CODES: tuple[str, ...] = (
    "onbekende-handeling",
    "onbekend-argument",
    "argument-ontbreekt",
    "argument-niet-tekst",
    "naamgrammatica",
    "beheerdienst",
    "appliance-certificaat",
    "niet-toegestaan",
    "doel-onbekend",
    "doel-nodig",
    "objectloze-vorm-niet-toegestaan",
    "run-naamgrammatica",
)


class Refusal(ActionError):
    """A refusal that carries STRUCTURE instead of a finished sentence.

    Why (design 3.3): the old refusal listed the allowed values of the one
    argument the caller named. That is less than the whole allowlist and MORE
    than the caller supplied - so at `openheid: beperkt` it handed real
    appliance object names through a door the disclosure switch does not
    guard. Since it is now `_act()` that turns this into text, and it does so
    through `render()`, the refusal must carry only two kinds of thing: a
    reason code, and values the caller typed itself.

    A subclass of `ActionError` on purpose: every existing `except
    ActionError` keeps catching it, so this is an addition and not a second
    error contract.
    """

    def __init__(self, code: str, tool: str, *, field: str | None = None, value: str | None = None) -> None:
        if code not in REFUSAL_CODES:
            raise ValueError(f"unknown refusal code: {code}")
        self.code = code
        self.tool = tool
        self.field = field
        self.value = value
        super().__init__(self.sentence())

    def sentence(self) -> str:
        """The Dutch line. Product copy, pinned in tests/test_product_surface.py.

        `value` is `!r`-quoted, not plain-quoted: it is the
        one interpolation here the CALLER supplies as free text. Reachable
        through "naamgrammatica" always with a value `_NAME` (letters,
        digits, dot, dash, underscore only) already refused, and through
        "beheerdienst" or "appliance-certificaat" only with a value that
        first SURVIVED that same grammar (`validate()` checks it in exactly
        that order, just below) - `!r` is a no-op for those three: it is
        BYTE-IDENTICAL to the plain single-quoting this line used to do
        (`f"'{value}'"` and `f"{value!r}"` agree whenever `value` carries no
        quote, backslash or control character - which is the whole pinned
        surface in test_product_surface.py).

        Corrected: that no-op claim used to
        cover "niet-toegestaan" too, and that is not true for every call
        site of this code. `validate()`'s own raise of it (just below) sits
        after the same grammar check, so `!r` is a no-op there as well - but
        `mcp_server.py`'s writing path builds this exact code DIRECTLY, with
        the RAW value the caller typed for an argument, the moment its
        pseudonym-resolution loop (reached only below `openheid: volledig`)
        fails to resolve that value as either a known real name or an
        issued pseudonym. That value has never been near `_NAME`, so `!r`
        is doing real work there: escaping whatever control character the
        caller wrote before it ever reaches this sentence.

        `!r` is the idiom this product already uses for exactly this class
        of issue (`start.py`'s doelnaam/candidate messages,
        `update_advice._ruleset`, `knowledge.py`'s refusal reasons), and it
        escapes a newline instead of emitting one. Measured: a `dienst` of
        `"lb\\n- verzonnen: alles is in orde [vastgesteld]"` used to split
        `Answer.to_text()`'s one finding line into a forged second line with
        no "geweigerd:" prefix and its own [vastgesteld] tag - see
        tests/test_handelen_zonder_code.py's
        `test_a_refusal_echoing_a_newline_at_volledig_does_not_forge_a_second_finding_line`
        and `..._vastgesteld_payload...`, both measured through the real
        `mcp_server._act()` weigerroute at `openheid: volledig`.

        Because `!r` genuinely escapes a value on that one call site, the
        masking seam that runs BELOW `openheid: volledig`
        (`disclosure._limit()`, via `mcp_server._act()`'s `caller_name`
        seams) has to search the rendered text for the ESCAPED spelling,
        not the raw one - `echoed_value()`, just below this class, is that
        spelling. See its own docstring for the leak this repairs.

        `tool` is never wrapped here: it is always one of this product's own
        seven write-tool names (mcp_server.py passes a literal per
        registration, never caller text) or, for "onbekende-handeling",
        whatever a direct `validate()` caller passed - never reachable with
        caller-typed text through any registered tool today.

        `field` is a key of `ARGUMENTS[tool]` - this product's own argument
        vocabulary - at every site EXCEPT "onbekend-argument" (corrected:
        this sentence used to say `field` is
        "always" a key of `ARGUMENTS[tool]`, one paragraph above a claim
        that "onbekend-argument"'s `field` is a joined-keys string instead -
        the two disagreed the moment both were written down together).
        "onbekend-argument" is the one code whose `field` is not a single
        argument name but a joined set of dict KEYS - and it is the
        exception in a second sense too: on every current call path
        (`mcp_server._act()`, `advice.py`) those keys are themselves
        literal Python keyword names this product's own code chose when it
        built the `arguments`/`raw_arguments` dict for that one call - never
        forwarded from a caller's own JSON key set (verified: both build
        that dict with hardcoded string literals, one per registered tool
        argument, so `unknown = set(arguments) - set(expected_fields)` in
        `validate()` can only ever be empty for a call built that way). So
        "onbekend-argument" is practically UNREACHABLE through any
        registered tool today, not merely safe if it somehow fired, and
        there is nothing untrusted left in either case to treat. Neither
        wrapping choice below is therefore a security fix, only a
        consistency one: "argument-ontbreekt" and "argument-niet-tekst" now
        `!r`-wrap `field` too purely because it is
        free - a bare argument name such as "dienst" carries no quote,
        backslash or control character, so `!r` reproduces the exact same
        single-quoted pin these two already had. "onbekend-argument" keeps
        its plain rendering: its `field` is the joined-keys string, not a
        single name, and wrapping THAT would change the pinned text rather
        than reproduce it - a cost this round does not spend.
        """
        tool, field, value = self.tool, self.field, self.value
        if self.code == "onbekende-handeling":
            return f"onbekende handeling '{tool}'"
        if self.code == "onbekend-argument":
            return f"onbekend argument voor {tool}: {field}"
        if self.code == "argument-ontbreekt":
            return f"argument {field!r} ontbreekt voor {tool}"
        if self.code == "argument-niet-tekst":
            return f"argument {field!r} moet tekst zijn voor {tool}"
        if self.code == "naamgrammatica":
            return (
                f"{value!r} voldoet niet aan de naamgrammatica (begint met een letter, daarna "
                "letters, cijfers, punt, streepje, underscore; maximaal 63 tekens)"
            )
        if self.code == "run-naamgrammatica":
            return (
                f"'{value}' voldoet niet aan de run-naamgrammatica (begint met een letter of "
                "cijfer, daarna letters, cijfers, punt, streepje, underscore; maximaal 128 "
                "tekens; geen gereserveerde Windows-apparaatnaam en niet eindigend op een punt)"
            )
        if self.code == "beheerdienst":
            return f"{value!r} is een beheerdienst van de appliance en blijft buiten bereik"
        if self.code == "appliance-certificaat":
            return f"{value!r} is een appliance-eigen certificaat en blijft buiten bereik"
        if self.code == "niet-toegestaan":
            if field is None:
                return f"'{tool}' staat niet op de allowlist voor dit doel"
            return f"{value!r} staat niet op de allowlist voor {field} van {tool}{_which_dienst(tool, field)}"
        if self.code == "doel-onbekend":
            return "onbekend doel; de allowlist in de configuratie kent dit doel niet"
        if self.code == "doel-nodig":
            return "geef doel op: de allowlist in de configuratie draagt meer dan een doelnaam"
        return (
            f"de allowlist zet {tool} als geheel aan of uit, maar {tool} vormt zijn object niet "
            "zelf; zet per argument de toegestane waarden"
        )

    def to_answer(self) -> Answer:
        """The refusal as an Answer, so `_act()` can put it through render().

        `subject_is_name=False`: the subject is the TOOL, this product's own
        vocabulary, and masking it would cost the reader the answer and write
        a tool name into the operator's pseudonym table.
        """
        return Answer(
            question=f"mag {self.tool} dit uitvoeren",
            findings=[
                Finding(
                    subject=self.tool,
                    outcome=f"geweigerd: {self.sentence()}",
                    certainty=Certainty.ESTABLISHED,
                    evidence=f"redencode {self.code}; allowlist uit de configuratie",
                    subject_is_name=False,
                )
            ],
        )


def echoed_value(value: str | None) -> str | None:
    """The exact spelling `Refusal.sentence()` echoes a caller-supplied
    `value` with, or `None` when there is none to echo.

    Exists for exactly one caller: `mcp_server._act()`'s three
    `caller_name=...` seams. Those feed
    `disclosure.render()`, which hands the value on to `disclosure._limit()`
    as the NEEDLE it searches the rendered answer text for and replaces
    with the fixed placeholder (`_UNKNOWN_NAME_IN_QUESTION`). Since I-a
    made `sentence()` `!r`-escape `value` instead of interpolating it
    plainly, the needle has to carry that same escaping too, or it stops
    matching the escaped spelling that is actually IN the text - the
    masking then silently does nothing instead of replacing anything.
    Measured at `openheid: beperkt` with a value carrying a newline or a
    backslash: before this fix the raw value stayed out of the text (it
    was masked correctly) but so did the placeholder, and after this fix
    both checks pass - see tests/test_handelen_zonder_code.py's
    `test_a_refusal_from_perform_on_the_proposal_path_at_beperkt_masks_a_value_with_a_newline_or_a_backslash`.

    `repr(value)[1:-1]`: the same escaping `sentence()`'s `!r` applies,
    with the two surrounding quote characters stripped off - `_limit()`'s
    search is a plain substring match, so it needs only the escaped BODY,
    never the quote marks around it. This cannot drift out of step with
    `sentence()`: both ultimately call the very same builtin `repr()` on
    the very same `value`, not two independent implementations that happen
    to agree today. If `sentence()`'s escaping choice (`!r`) ever changes,
    this function has to change with it - keep the two textually next to
    each other so that is hard to miss.

    For an ordinary value (no quote, backslash or control character) this
    is the value itself - `echoed_value(v) == v` - so every EXISTING
    `caller_name` pin from before this fix is unaffected.

    Fail-closed on a non-`str`, non-`None` value:
    every caller today hands this either `None` or a `str` - `_act()`'s
    pseudonym-resolution loop only ever passes `str(value).strip()`, and
    `validate()`'s own `isinstance` check refuses a non-`str` argument
    before any `Refusal` it raises can carry one as `value` - so a
    non-`str` here is an invariant violation, not a value worth
    reflecting on. Without this guard `repr()` still runs and still
    returns SOMETHING for any object - `echoed_value(5) == ''`,
    `echoed_value(3.5) == '.'` - a needle that then matches nothing or the
    wrong thing, and the masking this function exists for goes quiet
    instead of loud: precisely the shape of the finding this whole round
    repairs, one call site further down. Raising, not coercing with
    `str()` first: a silent `str()` would launder the same class of bug -
    a value reaching a text-composition seam with a shape nobody checked -
    one level further up the call stack instead of surfacing it here.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"echoed_value() verwacht str of None, kreeg {type(value).__name__}")
    return repr(value)[1:-1]


def validate(tool: str, arguments: dict, *, target: str, allowlist: Allowlist) -> dict:
    """Returns the normalized arguments, or raises `Refusal`. FOUR layers, in
    this order and no other: the tool is one this product has, the target has
    a section, the built-in denylist, the configured allowlist. The denylist
    stays BEFORE the allowlist and stays in code - an allowlist entry may
    never release a denylist name (design 3.2), and a denylist that can be
    configured away is not a denylist. Case-sensitive: NITRO object names are.

    Every refusal is a `Refusal` and therefore carries STRUCTURE: a reason
    code plus, at most, the value the caller typed itself. It no longer names
    the allowed values of the argument, and it no longer answers the "bedoelt
    u ...?" question about the typed term (C2, design 3.3). Both used to be
    facts about the CONFIGURATION rather than about the call, and `_act()`
    now turns this refusal into text through `render()` - so what stays in it
    must be safe at every openheid level, not only at 'volledig'. What a
    caller loses in guidance comes back along a route that is not an oracle:
    the reading advice says per item whether this server can carry it out,
    with the real name at the level where real names are allowed.
    """
    if tool not in ARGUMENTS:
        raise Refusal("onbekende-handeling", tool)
    if target not in allowlist.per_target:
        raise Refusal("doel-onbekend", tool)
    entry = allowlist.entry(target, tool)
    expected_fields = ARGUMENTS[tool]
    unknown = set(arguments) - set(expected_fields)
    if unknown:
        raise Refusal("onbekend-argument", tool, field=", ".join(sorted(unknown)))

    if isinstance(entry, bool):
        if tool not in OBJECTLESS_TOOLS:
            raise Refusal("objectloze-vorm-niet-toegestaan", tool)
        if not entry:
            raise Refusal("niet-toegestaan", tool)
        return {}
    if entry is None:
        raise Refusal("niet-toegestaan", tool)
    if tool in OBJECTLESS_TOOLS:
        raise Refusal("objectloze-vorm-niet-toegestaan", tool)

    clean: dict = {}
    for field in expected_fields:
        allowed_values = tuple(entry.get(field, ()))
        if field not in arguments:
            raise Refusal("argument-ontbreekt", tool, field=field)
        if not isinstance(arguments[field], str):
            raise Refusal("argument-niet-tekst", tool, field=field)
        value = arguments[field].strip()
        if not _NAME.fullmatch(value):
            raise Refusal("naamgrammatica", tool, field=field, value=value)
        if value.startswith(DENIED_PREFIXES):
            raise Refusal("beheerdienst", tool, field=field, value=value)
        if value in DENIED_NAMES:
            raise Refusal("appliance-certificaat", tool, field=field, value=value)
        if value not in allowed_values:
            raise Refusal("niet-toegestaan", tool, field=field, value=value)
        clean[field] = value
    return clean


def build_arguments(
    tool: str,
    arguments: dict,
    *,
    script: Path,
    fixture_dir: Path,
    preview: bool,
    bundle: str,
    target: str,
    allowlist: Allowlist,
) -> list[str]:
    clean = validate(tool, arguments, target=target, allowlist=allowlist)
    head = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", script_policy().execution_policy, "-File", str(script)]
    if tool == "certificaat_klaarzetten":
        name = clean["certnaam"]
        body = [
            "-Actie",
            "stage-cert",
            "-CertNaam",
            name,
            "-CertBestand",
            str(fixture_dir / "film" / f"{name}.cer"),
            "-SleutelBestand",
            str(fixture_dir / "film" / f"{name}.key"),
        ]
    elif tool == "certificaat_vervangen":
        body = ["-Actie", "replace-cert", "-VirtueleServer", clean["dienst"], "-NieuwCert", clean["nieuwcert"]]
    elif tool == "onderhoud_backup_maken":
        # The tool forms its own object (design 3.2, objectless allowlist
        # form), so the name is built HERE and the caller never supplies one.
        #
        # Defence in depth: `target` normally already passed
        # start.py's `_allowlist()`, which imports the SAME grammar
        # `backup_name()` checks here, so this branch should not be
        # reachable in the normal, config-driven path. A caller of
        # `build_arguments()`/`perform()` that bypasses that startup gate
        # (constructs an `Allowlist` directly, as a test does) gets an
        # honest `ActionError` here - this module's own error vocabulary -
        # instead of a raw `ValueError` a caller would have to know to catch
        # separately. `str(exc)` is safe to reuse unchanged: it names only
        # `target`, the operator's own configuration text, never anything
        # the appliance controls.
        #
        # This comment used to also claim that a
        # caller of the REAL SERVER got this same honest text. Measured,
        # that was false: `mcp_server._act()` only caught `ActionError`
        # around `validate()`, never around the `perform()` call that
        # reaches this branch - so the `ActionError` raised here propagated
        # out of `perform()` uncaught, past `_guarded_async`'s generic
        # `except Exception`, into `mask_error()`. The caller got the
        # byte-identical masked "Onverwachte fout ..." sentence either way.
        # `_act()` now catches `ActionError` around the `perform()` call too
        # (the same route `_failure()` already gives the `validate()` case),
        # so the server path is honest again - see the pin at
        # test_a_target_that_bypasses_the_startup_gate_gets_an_honest_answer_not_the_generic_mask
        # (tests/test_handelen_zonder_code.py).
        try:
            naam = backup_name(target, datetime.now(UTC))
        except ValueError as exc:
            raise ActionError(str(exc)) from None
        body = ["-Actie", "backup", "-BackupNaam", naam, "-Niveau", BACKUP_LEVEL]
    elif tool == "onderhoud_upgrade_fase":
        # This stays a DEFENSIVE guard, not a live
        # path: this tool's runner (Invoke-GjkUpgradeFase.ps1)
        # has an entirely different argument shape from the demo write
        # script's `-Actie ...` form (scripts/README.md) - `-Doel -Adres
        # -Fase -Run -Gebruiker -CredentialTarget
        # -HostsleutelVingerafdruk -Doelbuild -Firmwaremap -Ledger
        # -GatePython ... `, no `-Bundel`, and a `-WatIs` tail that is not
        # simply appended the way every other tool's is. `mcp_server._act()`
        # therefore never routes this tool through `perform()`/
        # `build_arguments()` at all - its own branch calls
        # `build_upgrade_arguments()` below directly, and starts the runner
        # itself (`start_detached()`), never through the demo write script's
        # `-WatIs`-then-real-run machinery this function drives. Falling
        # into the demo-tools `else` below would try `clean["dienst"]` on an
        # empty dict - a KeyError, not a refusal - so this stays an honest
        # ActionError rather than being deleted outright.
        raise ActionError(
            "onderhoud_upgrade_fase heeft geen argumentopbouw via build_arguments(); de "
            "faserunner wordt gestart via build_upgrade_arguments() en start_detached()"
        )
    elif tool == "config_opslaan":
        # The same defensive guard, for the same reason: this tool runs its
        # own script (Invoke-GjkConfigOpslaan.ps1) through `perform_save()`
        # and `build_save_arguments()` below, never through the demo write
        # script's `-Actie` shape.
        raise ActionError(
            "config_opslaan heeft geen argumentopbouw via build_arguments(); het opslagscript wordt "
            "gestart via build_save_arguments() en perform_save()"
        )
    else:
        body = [
            "-Actie",
            "disable-member",
            "-ServiceGroep",
            clean["dienst"],
            "-Server",
            clean["lid"],
            "-Poort",
            MEMBER_PORT,
        ]
    tail = ["-Bundel", bundle]
    if preview:
        tail.append("-WatIs")
    if tool == "dienst_lid_inschakelen":
        tail.append("-Ongedaan")
    return head + body + tail


def default_runner(arguments: list[str], timeout_s: int) -> tuple[int, str, str]:
    """Starts the write script as a REAL child process and waits on it, so
    the time limit ends the child POLITELY first.

    `subprocess.run(timeout=...)` was the old shape, and it ends a child with
    `kill()` and nothing else. The write script
    (`film\\Invoke-GjkLabWrite.ps1`) carries its guardrails in a `finally`
    block - compensation in reverse order plus a read-back - and a bare kill
    never asks for it. So: `terminate()` first, then wait out the grace
    period while still reading whatever the script manages to flush, and only
    what is STILL alive after that gets `collect._stop_child_process`'s hard
    treatment (a second terminate, a kill, and the streams closed).

    Platform note, stated instead of implied: on Windows `terminate()` IS
    `TerminateProcess`, the same call as `kill()` - see the docstring of
    `collect._stop_child_process`. The polite step therefore buys nothing on
    Windows; on POSIX it is SIGTERM before SIGKILL, which the script can trap.
    What this function guarantees on every platform is the ORDER and that the
    child is never left running.

    Raises `subprocess.TimeoutExpired` on the limit, exactly as the old shape
    did - `perform()` below turns that into the honest "NIET vastgesteld"
    answer, and it now carries whatever the child had already printed.
    """
    try:
        process = start_powershell(arguments)
    except (OSError, PowerShellMissing) as exc:
        raise ActionError(f"kon PowerShell niet starten: {exc}") from None
    return _wait_politely(process, timeout_s)


def typed_runner(arguments: list[str], timeout_s: int) -> tuple[int, str, str]:
    """`default_runner()` with a TYPED start failure (1.1): the routes next
    to the faserunner - `config_opslaan` (`perform_save`) and the live
    measurement of the pre-flight - say WHY nothing started, by type and
    without the text of the underlying error. Every branch here comes
    before a child exists: `start_powershell` raised, so no process was
    started. The wait, the time limit and the polite stop are the same as
    `default_runner()`'s; the demo write tools keep `default_runner()`."""
    try:
        process = start_powershell(arguments)
    except (OSError, PowerShellMissing) as exc:
        raise _not_started(exc) from None
    return _wait_politely(process, timeout_s)


def _not_started(exc: OSError | PowerShellMissing) -> ProcessNotStarted:
    """The typed error for a start failure that came before any child
    existed, chosen on the TYPE of `exc` (specific before general:
    `ScriptPinMismatch` and `ChildWorkingDirectoryUnusable` are subclasses
    of `PowerShellMissing`). Shared by `typed_runner()` and the `-WatIs`
    preview of the faserunner."""
    if isinstance(exc, ChildWorkingDirectoryUnusable):
        return RunnerWorkdirUnusable(exc)
    if isinstance(exc, ScriptPinMismatch):
        return ScriptPinRefused(exc)
    if isinstance(exc, PowerShellMissing):
        return PowerShellNotFound(exc)
    return RunnerProcessNotStarted(exc)


def _wait_politely(process: subprocess.Popen[str], timeout_s: int) -> tuple[int, str, str]:
    """The wait of `default_runner()`/`typed_runner()`: the child's output,
    or `subprocess.TimeoutExpired` after the polite stop."""
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        stdout, stderr = _stop_politely(process)
        raise subprocess.TimeoutExpired(
            # `process.args` instead of a second copy of the argument list:
            # the command line reported on a timeout must be the one that
            # really ran, absolute path and all.
            cmd=list(process.args),
            timeout=timeout_s,
            output=stdout,
            stderr=stderr,
        ) from None
    return process.returncode, stdout, stderr


def _stop_politely(process: subprocess.Popen[str]) -> tuple[str, str]:
    """terminate(), then read what the child still flushes, then kill.

    Returns whatever output was captured (empty strings when the child had to
    be killed): the timeout message is more useful with the script's own last
    lines under it than without them. Best-effort throughout - a child that
    just exited on its own must never turn a time limit into a crash.
    """
    try:
        process.terminate()
    except OSError:
        pass
    try:
        return process.communicate(timeout=_GRACE_S)
    except subprocess.TimeoutExpired:
        _stop_child_process(process, grace_s=_GRACE_S)
        return "", ""


def _marker(text: str, marker: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(marker):
            return line[len(marker) :].strip()
    return None


def _argument_value(command: list[str], flag: str) -> str | None:
    """The value that follows `flag` in `command`, or None if `flag` is absent.

    Reads the SAME argument list `perform()` is about to hand
    to the write script - the one this side already built, once, with
    `build_arguments()` - rather than asking the script to report the name
    back through a marker in its output. `flag` is `-BackupNaam` today (the
    only tool that forms its own object); a tool without that flag simply
    gets None back.
    """
    try:
        return command[command.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def perform(
    tool: str,
    arguments: dict,
    *,
    script: Path,
    fixture_dir: Path,
    preview: bool,
    bundle: str,
    target: str,
    allowlist: Allowlist,
    run=None,
    bevestiger: str | None = None,
) -> ActionResult:
    """`bevestiger` is never READ here - this layer has no script line to read
    it from. It is handed down by the caller (`mcp_server._act()`, which gets
    it from the code presenter) and carried onto every `ActionResult` this
    function returns, so a later reader of the result (the action register)
    sees the same value regardless of which branch produced it.

    `object_name` is likewise carried onto every branch, and
    for the same reason: it is read ONCE, here, from the argument list
    `build_arguments()` just built - never from the script's own output, and
    the clock inside `backup_name()` runs exactly once per call to this
    function, not once more to check what it produced.
    """
    command = build_arguments(
        tool,
        arguments,
        script=script,
        fixture_dir=fixture_dir,
        preview=preview,
        bundle=bundle,
        target=target,
        allowlist=allowlist,
    )
    object_name = _argument_value(command, "-BackupNaam")
    return _run_script(command, preview=preview, run=run, bevestiger=bevestiger, object_name=object_name)


def _run_script(
    command: list[str], *, preview: bool, run=None, bevestiger: str | None = None, object_name: str | None = None
) -> ActionResult:
    """Runs one write-script command (`run`, default `default_runner`, with
    `_TIMEOUT_S` and its polite stop) and reads its markers into an
    `ActionResult` - shared by `perform()` and `perform_save()`, so both read
    the same `[EINDSTATUS]`/`[TARGET]`/`[ACTIEID]` convention the same way."""
    runner = run or default_runner
    try:
        exit_code, stdout, stderr = runner(command, _TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        return ActionResult(
            ok=False,
            preview=preview,
            actie_id=None,
            target=None,
            eindstatus=f"tijdslimiet van {_TIMEOUT_S} seconden overschreden; het schrijfscript is afgebroken",
            text=(
                str(exc.stdout or "")
                + "\n[FOUT] tijdslimiet overschreden; of de appliance al gewijzigd is, is NIET vastgesteld - lees de stand terug voordat je opnieuw handelt"
            ),
            bevestiger=bevestiger,
            object_name=object_name,
        )
    eindstatus = _marker(stdout, "[EINDSTATUS]") or "(geen eindstatus)"
    text = stdout if not stderr else f"{stdout}\n{stderr}"
    if exit_code != 0:
        return ActionResult(
            False, preview, None, None, eindstatus, text, bevestiger=bevestiger, object_name=object_name
        )
    if preview:
        # Ook bij -WatIs meldt het schrijfscript zijn [TARGET]: de
        # bevestigingscode wordt aan DIT etiket gebonden, niet aan de
        # geconfigureerde scanlijst (zie mcp_server._act). CONTRACT: dat
        # etiket moet STABIEL zijn tussen twee -WatIs-aanroepen van
        # dezelfde poging - vooral bij onderhoud_backup_maken, waar deze
        # kant zelf een tijdgestempelde -BackupNaam vormt (backup_name())
        # maar het schrijfscript geen tijdstempel in [TARGET] mag zetten.
        # Een [TARGET] dat per aanroep verschilt verbrandt de code op de
        # tweede -WatIs (zie de moduledocstring hierboven en
        # tests/test_handelen_zonder_code.py,
        # test_CONTRACT_a_backup_target_label_that_drifts_per_invocation_burns_the_code_unused).
        target = _marker(stdout, "[TARGET]")
        return ActionResult(True, True, None, target, eindstatus, text, bevestiger=bevestiger, object_name=object_name)
    actie_id = _marker(stdout, "[ACTIEID]")
    target = _marker(stdout, "[TARGET]")
    if not actie_id or not target:
        return ActionResult(
            False,
            False,
            None,
            None,
            eindstatus,
            text + "\n[FOUT] het schrijfscript gaf geen actie-id of doel terug; de handeling telt niet als uitgevoerd",
            bevestiger=bevestiger,
            object_name=object_name,
        )
    return ActionResult(True, False, actie_id, target, eindstatus, text, bevestiger=bevestiger, object_name=object_name)


# ---------------------------------------------------------------------------
# onderhoud_upgrade_fase: the faserunner's own configuration,
# argument shape and detached start. A wholly separate contract from the six
# lines above `perform()` - the runner (scripts/Invoke-GjkUpgradeFase.ps1)
# takes an entirely different CLI, judges nothing itself (nsmcp.upgrade /
# nsmcp.upgrade_gate do, over the ledger) and, unlike every other write tool,
# is never waited on to completion: R1 alone measures 460 s of upload while
# a writing tool's own time limit (`_TIMEOUT_S` above) is 300 s. So
# `mcp_server._act()` gets its own execution branch for this tool instead of
# routing it through `perform()`; what belongs HERE is the configuration
# object, the phase-argument validation, the runner's own argument list, and
# starting it detached.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaintenanceConfig:
    """The `onderhoud` configuration section, built once by `start.py` from
    the configuration file and handed to `build_server()`. Everything a
    phase call needs that is NOT per-target: the runner script, where it
    writes its ledger, where the firmware bundle lives, the soak window in
    hours, and the SSH user it connects as. The two per-target fields
    (address, credential target, the pinned SSH host key) live on
    `target.Target` instead - one target's key is not another's (design
    decision 4)."""

    runner: Path
    ledgermap: Path
    firmwaremap: Path
    soak_uren: int
    ssh_gebruiker: str
    # OPTIONAL - the path to the action
    # register. `None` when not configured, and `build_upgrade_arguments()`
    # below then omits `-Actieregister` entirely (the runner's own contract:
    # optional on ITS parameter list too, `niet beoordeeld` when absent).
    actieregister: Path | None = None


def _phase_bool(value) -> bool:
    """`drift_geaccepteerd`/`doelbuild_geaccepteerd`/`oude_buildbomen_opruimen` arrive here as the
    literal string `'True'` or `'False'`, never as a real `bool`:
    `mcp_server._act()` stringifies every raw argument
    (`str(value).strip()`) before this module ever sees it, including the
    real booleans the tool's own signature declares. Anything else (absent,
    empty, a stray value) reads as `False` - fail-closed for two switches
    that respectively skip a drift check and remove a build tree, not
    fail-open."""
    return str(value).strip() == "True"


# Which phase-only argument belongs to which phase (scripts/README.md):
# given at any OTHER phase, that is not a
# different value to validate, it is an argument this call has no business
# carrying at all.
_PHASE_ONLY_ARGUMENTS: dict[str, str] = {
    "snapshotverwijzing": "R0",
    # The human acceptance of a target build below the security floor:
    # judged by R0's floor gate, so given at any other phase it has no gate
    # to open.
    "doelbuild_geaccepteerd": "R0",
    "drift_geaccepteerd": "R1",
    "oude_buildbomen_opruimen": "R1",
}


def validate_phase_arguments(arguments: dict) -> dict:
    """The phase arguments, checked on FORM - never against the allowlist.
    They name no appliance object (design 3.1), so `validate()` above has
    nothing to say about their VALUES, only about whether this tool may run
    on this target AT ALL (the objectless form it already checks, called
    separately by the caller). Returns the normalized phase-argument dict,
    or raises `Refusal`.
    """
    tool = "onderhoud_upgrade_fase"
    fase = str(arguments.get("fase", "")).strip().upper()
    if fase not in PHASE_NAMES:
        raise Refusal("onbekend-argument", tool, field="fase", value=fase)
    for naam, hoort_bij in _PHASE_ONLY_ARGUMENTS.items():
        gegeven = arguments.get(naam)
        aanwezig = bool(str(gegeven or "").strip()) if naam == "snapshotverwijzing" else _phase_bool(gegeven)
        if aanwezig and fase != hoort_bij:
            raise Refusal("onbekend-argument", tool, field=naam, value=fase)
    if fase == "R0" and not str(arguments.get("snapshotverwijzing", "")).strip():
        raise Refusal("argument-ontbreekt", tool, field="snapshotverwijzing")
    run = str(arguments.get("run", "")).strip()
    # Every phase but R0 CONTINUES an existing run - R0 forms a fresh
    # run-id itself (nsmcp.upgrade.run_id). Without this, an empty `run` on
    # R1..R6 would silently bind the ledger lookups to the empty string
    # instead of refusing - the same fail-closed discipline snapshotverwijzing
    # gets above, and the same reason code: this call is missing an
    # argument it needs, not a call the allowlist has an opinion about.
    if fase != "R0" and not run:
        raise Refusal("argument-ontbreekt", tool, field="run")
    # `run` becomes a filesystem path STEM, never validated against the
    # allowlist (design 3.1: it names no appliance object) but very much
    # untrusted operator input all the same - `mcp_server._upgrade_work()`
    # builds `onderhoud.ledgermap / f"{run}.jsonl"` from exactly this
    # value. Checked here, on FORM, the same seam every other phase
    # argument is checked on - not only when it is missing (above) but
    # also when it is present and unsafe: a path separator, '..', a drive
    # letter, a UNC prefix, an alternate-data-stream marker, a reserved
    # Windows device name, a trailing dot, or a control character.
    # `is_safe_run_name()` (nsmcp.upgrade) is the ONE implementation this
    # module shares with the ADOPTED-run check in `mcp_server.py` - a run
    # name read back out of a ledger row instead of typed by the operator.
    if run and not is_safe_run_name(run):
        raise Refusal("run-naamgrammatica", tool, field="run", value=run)
    return {
        "fase": fase,
        "run": run,
        "snapshotverwijzing": str(arguments.get("snapshotverwijzing", "")).strip(),
        "doelbuild_geaccepteerd": _phase_bool(arguments.get("doelbuild_geaccepteerd")),
        "drift_geaccepteerd": _phase_bool(arguments.get("drift_geaccepteerd")),
        "oude_buildbomen_opruimen": _phase_bool(arguments.get("oude_buildbomen_opruimen")),
        # Measured on the lab (8-9-2026): a STANDALONE appliance reports itself as
        # `Master State: Primary` in `show ha node`, so the secondary gate closed on
        # every box without a peer. Downtime on a standalone box is a HUMAN decision;
        # this switch records it and is read by every phase that measures the role.
        "standalone_geaccepteerd": _phase_bool(arguments.get("standalone_geaccepteerd")),
    }


# `build-<tak>-<build>_nc_64.tgz` - the same filename shape
# `mcp_server._bundle_mb()` already reads for size, named here once so the
# doelbuild derivation below and that docstring cannot drift apart. `\Z`, not
# `$`: `$` also matches just before a trailing newline, and the runner's own
# bundle check ends at `\z` for the same reason.
_FIRMWARE_BUNDLE_RE = re.compile(r"^build-(?P<tak>[0-9]+(?:\.[0-9]+)*)-(?P<build>[0-9]+(?:\.[0-9]+)*)_nc_64\.tgz\Z")


@dataclass(frozen=True)
class FirmwareBundle:
    """The ONE bundle in `onderhoud.firmwaremap`: which build it installs
    (`<tak>-<build>`), its file name, and its size in whole MB - rounded the
    way the runner rounds the same file for its own disk gate
    (`[math]::Round($bundelBestand.Length / 1MB)`, round half to even, which
    is also what Python's `round()` does)."""

    build: str
    naam: str
    mb: int


# The reason for zero or more than one bundle WITHOUT the local path of the
# firmware directory or the names of the files in it, for every disclosure
# level below 'volledig'. The full sentence (`str()` of the error) names the
# path or the bundles; `zonder_pad` says only what the directory holds.
FIRMWAREMAP_GEEN_BUNDEL_TEXT = "de ingestelde firmwaremap bevat geen bundel"
FIRMWAREMAP_MEER_BUNDELS_TEXT = "de ingestelde firmwaremap bevat meer dan een bundel"


class FirmwareBundleError(ActionError):
    """Zero or more than one bundle in `onderhoud.firmwaremap`: an
    `ActionError` whose `zonder_pad` is the same reason without the local
    path or file names - the server shows that one below 'volledig'."""

    def __init__(self, text: str, zonder_pad: str):
        super().__init__(text)
        self.zonder_pad = zonder_pad


def firmware_target_build(firmwaremap: Path) -> FirmwareBundle:
    """The build this window installs (`<tak>-<build>`, e.g. `14.1-72.57`),
    read from the ONE firmware bundle in `onderhoud.firmwaremap` - never a
    caller argument - together with that bundle's size. The tool's own
    signature carries no `doelbuild` parameter and none of the example calls
    name one either: the bundle placed in `firmwaremap` IS the choice, made
    by whoever put it there. ONE source for the target build AND for the
    size the pre-flight uses (`mcp_server._bundle_mb()`), so one directory
    has one policy: zero or more than one bundle is no target build and no
    size either.

    Zero or more than one candidate is an honest 'cannot describe this
    call', not a start error (it is not among the task's seven pinned
    ones - a firmware directory can legitimately be prepared after the
    server started) - `ActionError`, the same contract the earlier
    placeholder used to give this whole tool."""
    try:
        kandidaten = sorted(p.name for p in Path(firmwaremap).iterdir() if _FIRMWARE_BUNDLE_RE.match(p.name))
    except OSError as exc:
        raise ActionError(f"onderhoud.firmwaremap is niet leesbaar: {exc}") from None
    if not kandidaten:
        raise FirmwareBundleError(
            f"onderhoud.firmwaremap draagt geen firmwarebundel van de vorm build-<tak>-<build>_nc_64.tgz: {firmwaremap}",
            FIRMWAREMAP_GEEN_BUNDEL_TEXT,
        )
    if len(kandidaten) > 1:
        raise FirmwareBundleError(
            "onderhoud.firmwaremap draagt meer dan een firmwarebundel; er is dan geen "
            f"eenduidige doelbuild: {', '.join(kandidaten)}",
            FIRMWAREMAP_MEER_BUNDELS_TEXT,
        )
    match = _FIRMWARE_BUNDLE_RE.match(kandidaten[0])
    try:
        grootte = (Path(firmwaremap) / kandidaten[0]).stat().st_size
    except OSError as exc:
        raise ActionError(f"de grootte van de firmwarebundel is niet leesbaar: {exc}") from None
    return FirmwareBundle(
        build=f"{match.group('tak')}-{match.group('build')}",
        naam=kandidaten[0],
        mb=round(grootte / (1024 * 1024)),
    )


def _firmware_target_build(firmwaremap: Path) -> str:
    """The target build alone - see `firmware_target_build()`."""
    return firmware_target_build(firmwaremap).build


def _posh_ssh_wire_fingerprint(stored: str) -> str:
    """Converts `target.py`'s STORAGE/COMPARISON form of an SSH host-key
    fingerprint (`_normalize_fingerprint`: separators stripped, uppercase,
    two hex characters per byte) to Posh-SSH 3.2.7's own CANONICAL WIRE
    form - the ONE seam where this conversion happens.

    Posh-SSH's `NewSessionBase.cs` (lines 312-325) formats the OFFERED host
    key as `{0:x}:` joined per byte - lowercase, colon-separated, and
    UNPADDED (a byte below 0x10 renders as a single hex digit, not two) -
    and then compares that string against what `New-SSHTrustedHost` was
    given with a plain `==`. `target.py`'s stored form is uppercase, has no
    separators, and always carries two hex characters per byte. Passed
    straight through, the two forms never compare equal even when the
    underlying bytes are identical: `CanTrust` is `false`, SSH.NET throws
    "Key exchange negotiation failed.", and every phase R1..R6 dies before
    it opens a session - a genuine host-key mismatch then reads identically
    to that same failure (see `_GjkIsHostsleutelfout` in
    `scripts/GjkUpgrade-Ssh.ps1` and `hostkey_session_gate` below).

    `target.py`'s normalisation stays exactly as it is - the storage and
    comparison form used everywhere else in this codebase (target equality,
    the targets-file round trip). This function only shapes the value for
    the one wire it actually has to match: the PowerShell argument list.

    An empty/`None` input yields `''` (the "no pin" case `build_
    upgrade_arguments()` already passes through unchanged; `hostkey_gate`/
    `hostkey_session_gate` treat that as `dicht`, never `open`)."""
    text = str(stored or "").strip()
    if not text:
        return ""
    if len(text) % 2 != 0:
        raise ValueError(f"vingerafdruk heeft een oneven aantal hex-tekens: {text!r}")
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"vingerafdruk is geen geldige hex-tekst: {text!r}") from None
    return ":".join(f"{b:x}" for b in raw)


def build_upgrade_arguments(
    clean: dict,
    *,
    target,
    onderhoud: MaintenanceConfig,
    run_name: str,
    actie_id: str,
    bevestiger: str | None,
    preview: bool,
    export_dir: Path | None = None,
    forbidden_addresses: tuple[str, ...] = (),
    floor_build: str = "",
    floor_bulletin: str = "",
    current_build: str = "",
    floor_package: str = "",
    floor_package_date: str = "",
) -> list[str]:
    """The runner's OWN argument list (scripts/README.md: `-Doel -Adres
    -Fase -Run -Gebruiker -CredentialTarget -HostsleutelVingerafdruk
    -Doelbuild -Firmwaremap -Ledger -GatePython ...`) - not the demo write
    script's `-Actie ...-Bundel` shape `build_arguments()` above builds, so
    this does not reuse it. `clean` is the already-validated phase-argument
    dict from `validate_phase_arguments()`; `target` is the `target.Target`
    this call runs on; `actie_id` is `''` on a preview (the runner's own
    contract: "-WatIs ... is een leeg -Actieid juist normaal") and the
    value read back off the preview's own `[ACTIEID]` line on a confirmed
    run. `-Actieregister` is passed when `onderhoud.actieregister` is
    configured - the PATH, never an invented
    one: `mcp_server._act()` writes a `register_line()` row to it after
    every executed write action, so a configured path carries real
    evidence for R0's gates to read; omitted entirely when the key
    is absent, the same optional-on-both-sides shape `-ExportRoot` already
    has.

    `forbidden_addresses`: `handelen.verboden_adressen`
    from the configuration, read and validated by `start.py`, empty by
    default. Passed to the runner as ONE comma-joined token
    (`-VerbodenAdressen <addr>,<addr>`) only when non-empty - the runner's
    own parameter defaults to an empty array too, so omitting the flag
    entirely when there is nothing to pass is not a different code path,
    just a shorter argument list. Measured: `powershell.exe -File` binds
    only the first of two space-separated values to a `[string[]]`
    parameter and hands the second to positional binding (on R0 it became
    the snapshot reference); the runner splits the token on the comma
    itself and refuses any stray positional value. The runner's static name
    guard (`lab-01`) is unaffected either way; this only adds address forms,
    which never belong in this repository's own source.

    `floor_build`/`floor_bulletin`: the security floor the caller derived
    (`update_advice.export_floor`), R0 only - R0's floor gate judges the
    target build against it, with `-DoelbuildGeaccepteerd` as the human way
    past a target build below it, or past a floor that is not known at all.
    Each travels only in the runner's own form; a floor that has no such
    form (a FIPS train, digits of another script) is left out together with
    the acceptance, and the gate then closes on "no floor" instead of the
    runner refusing to bind at all.

    `current_build`: the build the appliance runs according to the export
    (`update_advice.export_current_build`), R0 only, as `-Huidigebuild` -
    R0's floor gate closes a target build in another release line than this
    one, with or without acceptance. Empty is "not known": the gate then
    opens only on the acceptance, as a human decision. A current build that
    IS known but has no runner form is not "not known": it is left out
    together with the acceptance, the same rule as the floor.

    `floor_package`/`floor_package_date`: the version and date of the pinned
    knowledge package the floor came from, R0 only and only together with a
    floor that travels, as `-VloerPakket`/`-VloerPakketDatum`. R0's evidence
    names them and warns when the package is old; a label without the
    runner's form (`upgrade.runner_package`) stays behind, and the evidence
    then says the package was not handed over. Neither ever opens or closes
    a gate.
    """
    doelbuild = _firmware_target_build(onderhoud.firmwaremap)
    args = [
        "-Doel",
        target.name,
        "-Adres",
        target.address,
        "-Fase",
        clean["fase"],
        "-Run",
        run_name,
        "-Gebruiker",
        onderhoud.ssh_gebruiker,
        "-CredentialTarget",
        target.credential_target,
        "-HostsleutelVingerafdruk",
        _posh_ssh_wire_fingerprint(target.ssh_hostsleutel_vingerafdruk),
        "-Doelbuild",
        doelbuild,
        "-Firmwaremap",
        str(onderhoud.firmwaremap),
        "-Ledger",
        str(Path(onderhoud.ledgermap) / f"{run_name}.jsonl"),
        "-GatePython",
        sys.executable,
        "-SoakUren",
        str(onderhoud.soak_uren),
    ]
    if clean["snapshotverwijzing"]:
        args += ["-Snapshotverwijzing", clean["snapshotverwijzing"]]
    if clean["fase"] == "R0":
        huidig = runner_current_build(current_build)
        if huidig:
            args += ["-Huidigebuild", huidig]
        vloer, bulletin = runner_floor(floor_build, floor_bulletin)
        if vloer:
            args += ["-Vloerbuild", vloer]
        if bulletin:
            args += ["-VloerBulletin", bulletin]
        pakket, pakket_datum = runner_package(floor_package, floor_package_date) if vloer else ("", "")
        if pakket:
            args += ["-VloerPakket", pakket, "-VloerPakketDatum", pakket_datum]
        # The acceptance travels with a floor and a current build the runner
        # sees, or when either is not known at all. One that IS known but
        # has no runner form (a FIPS train, digits of another script) is
        # neither: the runner would read its absence as "not known" and open
        # on the acceptance, so it stays here and R0 closes.
        if clean.get("doelbuild_geaccepteerd") and (vloer or not floor_build) and (huidig or not current_build):
            args.append("-DoelbuildGeaccepteerd")
    if onderhoud.actieregister is not None:
        args += ["-Actieregister", str(onderhoud.actieregister)]
    if export_dir is not None:
        args += ["-ExportRoot", str(export_dir)]
    if forbidden_addresses:
        args += ["-VerbodenAdressen", ",".join(forbidden_addresses)]
    if clean["drift_geaccepteerd"]:
        args.append("-DriftGeaccepteerd")
    if clean.get("standalone_geaccepteerd"):
        args.append("-StandaloneGeaccepteerd")
    if clean["oude_buildbomen_opruimen"]:
        args.append("-OudeBuildbomenOpruimen")
    if actie_id:
        args += ["-Actieid", actie_id]
    if bevestiger:
        args += ["-Bevestiger", bevestiger]
    if preview:
        args.append("-WatIs")
    return args


def upgrade_command(runner: Path, script_arguments: list[str]) -> list[str]:
    """The full process argv to launch `runner` with `script_arguments`.

    A `.ps1` runner (the real product) resolves through
    `nsmcp.powershell.powershell_path()` - the same absolute-path
    resolution `default_runner()` above already uses via
    `start_powershell()` - with its own existence check, never a bare
    `'powershell.exe'` that lets Windows search the working directory first.
    A `.py` runner (the fake runner these tests use, and the pattern
    `code_channel.SsoCodeChannel.__call__` already uses for its presenter)
    is launched directly with THIS process's own interpreter - portable to
    a CI runner with no PowerShell at all. That interpreter is
    `sys._base_executable`, never bare `sys.executable`: on a venv whose own `Scripts/python.exe`
    is a launcher/trampoline binary (re-execing the real interpreter as a
    child rather than being a copy of it - `uv venv`-style, not every venv),
    `sys.executable` names that trampoline. `start_detached()` below always
    launches its argv with Windows' `DETACHED_PROCESS` (no console at all,
    by design - see that function's own docstring), and a trampoline handed
    `DETACHED_PROCESS` from a process tree that itself has no console
    deadlocks in its own interpreter-startup relaunch, before the runner
    script's first line ever executes - never writing `fase_gestart`, so
    every confirmed run times out at `START_WAIT_S` no matter how fast the
    runner itself would have been. `sys._base_executable` is CPython's own
    documented seam for exactly this (the `venv` module uses it itself) and
    resolves to the real interpreter unconditionally, whether the running
    python.exe is a trampoline or (the common case) an ordinary copy - so
    this is not a fallback for a rare case, it is simply the correct value
    to launch a DETACHED child with. Falls back to `sys.executable` only if
    the attribute is ever absent (non-CPython)."""
    runner = Path(runner)
    # 1.0.2: the runner and every script beside it (its transport,
    # dot-sourced by name; an unpinned one refuses) against `scriptpin`,
    # right before the argv is handed to a process starter.
    check_script_pins(runner)
    if runner.suffix.lower() == ".py":
        interpreter = getattr(sys, "_base_executable", None) or sys.executable
        # 1.0.3: isolated mode (`-I`), like every Python child of this
        # product: no working directory, script directory or PYTHON*
        # variable on the module path of the child.
        return [interpreter, "-I", str(runner), *script_arguments]
    exe = powershell_path()
    if not exe.is_file():
        raise PowerShellMissing(f"Windows PowerShell niet gevonden op {exe}; er wordt geen proces gestart")
    return [
        str(exe),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        script_policy().execution_policy,
        "-File",
        str(runner),
        *script_arguments,
    ]


def _default_upgrade_process_runner(argv: list[str], timeout_s: int) -> tuple[int, str, str]:
    """Runs the faserunner's `-WatIs` preview as a REAL child process and
    waits for it - fast by contract (scripts/README.md: `-WatIs` "drukt
    beide etiketten af ... en stopt dan (exitcode 0)"; no session opens, no
    ledger line). The CONFIRMED run never calls this: it goes through
    `start_detached()` below instead, for exactly the reason
    `default_runner()` above exists for the demo tools' 300 s ceiling - R1
    alone measures 460 s of upload."""
    try:
        process = subprocess.Popen(
            argv,
            cwd=child_working_directory(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, PowerShellMissing) as exc:
        # 1.1: typed, like the confirmed start - no child exists here.
        raise _not_started(exc) from None
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        stdout, stderr = _stop_politely(process)
        raise subprocess.TimeoutExpired(
            cmd=argv,
            timeout=timeout_s,
            output=stdout,
            stderr=stderr,
        ) from None
    return process.returncode, stdout, stderr


def run_upgrade_preview(
    script_arguments: list[str],
    *,
    runner: Path,
    timeout_s: int = _TIMEOUT_S,
) -> tuple[int, str, str]:
    """Builds the full argv for `runner` and runs the preview, waiting for
    it - the ONE call site for both `upgrade_command()` and
    `_default_upgrade_process_runner()`, so a caller never has to build
    the interpreter dispatch itself."""
    try:
        argv = upgrade_command(runner, script_arguments)
    except PowerShellMissing as exc:
        # 1.1: the pin check and the interpreter dispatch, typed - the
        # preview runs before every confirmed start, so this is where a
        # changed script or a missing PowerShell is met first.
        raise _not_started(exc) from None
    return _default_upgrade_process_runner(argv, timeout_s)


# ---------------------------------------------------------------------------
# The small SSH scripts next to the faserunner: the live read of the free
# space on /var (scripts/Invoke-GjkLiveMeting.ps1, a READ for check 8 of the
# pre-flight). They use the runner's own transport (GjkUpgrade-Ssh.ps1: the
# pinned host key, the credential from Windows Credential Manager, the
# banner filter) and are found the way the runner finds that transport:
# next to the configured runner, never through a configuration key of their
# own. Started through `default_runner()` above - one PowerShell starter, the
# same polite stop on the time limit.
# ---------------------------------------------------------------------------
LIVE_MEASURE_SCRIPT = "Invoke-GjkLiveMeting.ps1"
# The same two minutes the collector route gets for its one resource: a
# pre-flight that hangs for a quarter of an hour on one measurement holds up
# the eight checks that need no appliance at all.
LIVE_MEASURE_TIMEOUT_S = 120


def sibling_script(onderhoud: MaintenanceConfig, name: str) -> Path:
    """`name` in the directory of the configured faserunner."""
    return Path(onderhoud.runner).parent / name


def _ssh_script_arguments(target, onderhoud: MaintenanceConfig, forbidden_addresses: tuple[str, ...]) -> list[str]:
    """The arguments every small SSH script shares with the runner: which
    box, as whom, with which credential target and which pinned host key.

    `-VerbodenAdressen` travels as ONE comma-joined token, last on the
    list. Measured: `powershell.exe -File` binds only the first of two
    space-separated values to a `[string[]]` parameter and hands the second
    to positional binding; the scripts split the token on the comma
    themselves and refuse any stray positional argument."""
    args = [
        "-Doel",
        target.name,
        "-Adres",
        target.address,
        "-Gebruiker",
        onderhoud.ssh_gebruiker,
        "-CredentialTarget",
        target.credential_target,
        "-HostsleutelVingerafdruk",
        _posh_ssh_wire_fingerprint(target.ssh_hostsleutel_vingerafdruk),
    ]
    if forbidden_addresses:
        args += ["-VerbodenAdressen", ",".join(forbidden_addresses)]
    return args


def build_live_measure_arguments(
    target, onderhoud: MaintenanceConfig, *, forbidden_addresses: tuple[str, ...] = ()
) -> list[str]:
    """The read script's arguments for the one measurement it knows."""
    return ["-Meting", "vrije-ruimte", *_ssh_script_arguments(target, onderhoud, forbidden_addresses)]


def script_command(script: Path, script_arguments: list[str]) -> list[str]:
    """The PowerShell arguments that run `script` - the same head
    `build_arguments()` gives the write script."""
    return [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        script_policy().execution_policy,
        "-File",
        str(script),
        *script_arguments,
    ]


# ---------------------------------------------------------------------------
# config_opslaan: `save ns config` over SSH, through the runner's own
# transport, in its own small script (scripts/Invoke-GjkConfigOpslaan.ps1).
# The script decides nothing: the role check goes through
# `python -m nsmcp.upgrade_measure` (`save_role_gate`), and the read-back of
# `show ns config` is judged in the server process (`backup.save_readback_ok`).
# Preview and real run go through the same `_run_script()` as the other write
# tools - the same time limit, the same polite stop, the same markers.
# ---------------------------------------------------------------------------
SAVE_SCRIPT = "Invoke-GjkConfigOpslaan.ps1"
SAVE_TOOL = "config_opslaan"
_SAVE_ACTION_PREFIX = "config-opslaan-"


def build_save_arguments(
    target,
    onderhoud: MaintenanceConfig,
    *,
    preview: bool,
    actie_id: str,
    forbidden_addresses: tuple[str, ...] = (),
) -> list[str]:
    """The save script's arguments, in the style of `build_upgrade_arguments()`.

    A target without a pinned SSH host key is refused HERE, before any
    process starts: the script pins the key and never accepts one, so a call
    without a pin could only fail later, less clearly. The confirmer is not
    an argument: it travels on the `ActionResult` into the action register
    and the action log, exactly as it does for the other write tools."""
    if not str(getattr(target, "ssh_hostsleutel_vingerafdruk", "") or "").strip():
        raise ActionError(
            f"doel {target.name} draagt geen ssh_hostsleutel_vingerafdruk; config_opslaan pint de hostsleutel en "
            "slaat zonder gepinde sleutel niet op"
        )
    try:
        args = _ssh_script_arguments(target, onderhoud, forbidden_addresses)
    except ValueError as exc:
        raise ActionError(f"de gepinde hostsleutel van doel {target.name} is ongeldig: {exc}") from None
    args += ["-GatePython", sys.executable]
    if actie_id:
        args += ["-Actieid", actie_id]
    if preview:
        args.append("-WatIs")
    return args


def perform_save(
    *,
    target,
    onderhoud: MaintenanceConfig,
    allowlist: Allowlist,
    preview: bool,
    forbidden_addresses: tuple[str, ...] = (),
    run=None,
    bevestiger: str | None = None,
) -> ActionResult:
    """`perform()` for `config_opslaan`. The allowlist is checked again here
    (the same second `validate()` `perform()` makes through
    `build_arguments()`), the script must stand next to the faserunner, and
    the real run carries an action id THIS side formed: the script echoes it
    as `[ACTIEID]` right before `save ns config`, and a run that echoes
    anything else - or nothing - does not count as executed. Whether the
    save took is NOT decided here: that is the read-back
    (`backup.save_readback_ok`), in the caller."""
    validate(SAVE_TOOL, {}, target=target.name, allowlist=allowlist)
    script = sibling_script(onderhoud, SAVE_SCRIPT)
    if not script.is_file():
        raise ActionError(f"het opslagscript {SAVE_SCRIPT} staat niet naast de faserunner; er is niets gestart")
    actie_id = "" if preview else _SAVE_ACTION_PREFIX + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    command = script_command(
        script,
        build_save_arguments(
            target, onderhoud, preview=preview, actie_id=actie_id, forbidden_addresses=forbidden_addresses
        ),
    )
    # 1.1: `typed_runner`, so a script that did not start says why by type.
    result = _run_script(command, preview=preview, run=run or typed_runner, bevestiger=bevestiger)
    if not preview and result.ok and result.actie_id != actie_id:
        return replace(
            result,
            ok=False,
            actie_id=None,
            target=None,
            text=result.text
            + "\n[FOUT] het opslagscript meldde een ander actie-id dan deze kant meegaf; de handeling telt niet als "
            "uitgevoerd",
        )
    return result


# ---------------------------------------------------------------------------
# Runner lifetime on Windows (integration on the release, 14-9-2026). MEASURED
# on the workstation, not reasoned: every MCP server that the desktop client
# starts sits inside a Windows Job Object (IsProcessInJob on all six running
# product servers: True). A Job Object may end its members when its last
# handle closes, so a runner that merely runs hidden could share the host's
# lifetime. The product therefore asks to break away from the host's job
# first (CREATE_BREAKAWAY_FROM_JOB - granted only when the job allows it),
# then MEASURES where the child ended up and reports that as a fact in the
# answer - instead of refusing every job-hosted server (which would refuse
# the one host this product is built for) or claiming a detachment it never
# checked. Whether a host-bound runner really dies with its host is NOT
# measured (docs/klant/OPENSTAANDE-METINGEN.md); the answer says which of
# the two it got.
# ---------------------------------------------------------------------------
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5

RUNNER_LOSGEKOPPELD = "losgekoppeld: de faserunner draait buiten het Job Object van deze host"
RUNNER_HOST_GEBONDEN = (
    "host-gebonden: de faserunner draait binnen het Job Object van deze host en kan eindigen wanneer deze host afsluit"
)
RUNNER_NIET_BEOORDEELD = "niet beoordeeld: de Job Object-binding van de faserunner is niet gemeten"


def _process_in_job(pid: int | None = None) -> bool | None:
    """True/False when Windows answered whether the process (this one when
    `pid` is None) sits inside a Job Object; None when there was no answer
    (not Windows, or the API refused). None is an evidence gap, never a No."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel.IsProcessInJob.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    if pid is None:
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        handle, owned = kernel.GetCurrentProcess(), False
    else:
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        handle, owned = kernel.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid), True
        if not handle:
            return None
    try:
        in_job = wintypes.BOOL()
        if not kernel.IsProcessInJob(handle, None, ctypes.byref(in_job)):
            return None
        return bool(in_job.value)
    finally:
        if owned:
            kernel.CloseHandle(handle)


def start_detached(arguments: list[str], *, log_path: Path) -> str:
    """Starts the runner and does NOT wait for it. Returns the MEASURED
    lifetime of the child for the answer: `RUNNER_LOSGEKOPPELD`,
    `RUNNER_HOST_GEBONDEN` or `RUNNER_NIET_BEOORDEELD` - never a fourth text.

    Why (design 3.5): `_TIMEOUT_S` is 300 s and R1 alone measured 460 s of
    upload. A phase that waits on the tool falls over on the TOOL's limit
    instead of its own. So the process is detached, its stdout and stderr
    go to a file next to the ledger (diagnostics, never the verdict), and
    the tool then waits at most `START_WAIT_S` for the LEDGER line
    `fase_gestart` (`nsmcp.upgrade.wait_for_start`, called by the caller,
    not by this function).

    `arguments` is the FULL process argv (built by `upgrade_command()`, the
    same dispatch `run_upgrade_preview()` uses) - this function itself
    launches exactly that argv detached, and knows nothing about PowerShell
    or Python specifically. On Windows: `CREATE_NO_WINDOW |
    CREATE_NEW_PROCESS_GROUP` (a hidden console of its own - NOT
    DETACHED_PROCESS, see the measured note below), so the child does not
    share this process's console or receive its Ctrl+C. Whether it also
    OUTLIVES this process is a separate question - the Job Object
    measurement above - and is returned, never assumed. Elsewhere:
    `start_new_session=True`, the POSIX equivalent."""
    log_path = Path(log_path)
    extra_kwargs: dict = {}
    host_in_job: bool | None = None
    if sys.platform == "win32":
        # MEASURED on the lab (8-9-2026), not reasoned: with DETACHED_PROCESS
        # Windows PowerShell 5.1 has no console at all and then exits 0
        # IMMEDIATELY without running a single statement - even
        # `-Command "exit 7"` returns 0 and writes nothing to the redirected
        # stdout. The real .ps1 runner therefore never wrote `fase_gestart`
        # and every phase died with "geen regel fase_gestart binnen 20
        # seconden"; the .py NEP-runner of the tests never noticed, because
        # a Python interpreter does not need a console. CREATE_NO_WINDOW
        # gives the child its OWN hidden console: it runs, its output lands
        # in the log, it does not share this process's console (so no
        # Ctrl+C from here reaches it: CREATE_NEW_PROCESS_GROUP). Pinned by
        # tests/test_start_detached_windows.py against the real powershell.exe.
        extra_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        host_in_job = _process_in_job()
    else:
        extra_kwargs["start_new_session"] = True
    # 1.1: the three typed errors below are raised ONLY where it is proven
    # that no child exists: before `Popen` (the log file, the working
    # directory) or when `Popen` failed on every attempt it got. Once
    # `Popen` returned a child, every later failure - the Job Object
    # measurement below included - leaves this function as whatever it is,
    # never as one of the three: a child may exist, so the caller keeps the
    # target reserved.
    try:
        log_file = open(log_path, "a", encoding="utf-8", newline="\n")
    except OSError as exc:
        raise RunnerLogUnopenable(exc) from None
    # Inside a job: first WITH breakaway (the job may allow it), then, only
    # when the job refuses that (ERROR_ACCESS_DENIED), without - and the
    # measurement below says which lifetime the child actually got.
    attempts = [extra_kwargs]
    if host_in_job:
        attempts.insert(
            0,
            {
                **extra_kwargs,
                "creationflags": extra_kwargs["creationflags"] | _CREATE_BREAKAWAY_FROM_JOB,
            },
        )
    child = None
    try:
        # 1.0.3: a fixed working directory, never the server's own one.
        try:
            working_directory = child_working_directory()
        except ChildWorkingDirectoryUnusable as exc:
            raise RunnerWorkdirUnusable(exc) from None
        for index, kwargs in enumerate(attempts):
            try:
                child = subprocess.Popen(
                    arguments,
                    cwd=working_directory,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    close_fds=True,
                    **kwargs,
                )
                break
            except OSError as exc:
                refused_breakaway = index + 1 < len(attempts) and getattr(exc, "winerror", None) == _ERROR_ACCESS_DENIED
                if not refused_breakaway:
                    raise RunnerProcessNotStarted(exc) from None
    finally:
        log_file.close()
    if sys.platform != "win32":
        return RUNNER_LOSGEKOPPELD
    child_in_job = _process_in_job(child.pid)
    if child_in_job is False:
        return RUNNER_LOSGEKOPPELD
    if child_in_job is True and host_in_job is True:
        return RUNNER_HOST_GEBONDEN
    return RUNNER_NIET_BEOORDEELD
