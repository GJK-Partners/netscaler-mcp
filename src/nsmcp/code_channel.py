"""The channel that carries a confirmation code to the OPERATOR.

Why this module exists, measured and not assumed: in three headless
practice runs against the lab, the language model called a writing tool,
received the proposal WITH the code in it, and called the same tool again
with that code inside the same turn - five out of five writing opportunities
in one run. The human was
never shown the proposal and never said yes. The two-step confirmation
survived as a mechanism and died as a guarantee, because both steps lived
inside the model's own agentic loop.

The repair is architectural, not a wording change: the code no longer
travels in the tool result. It goes out through a channel the model cannot
read - a window on the machine where the server runs, or a file the operator
chose - and the second step therefore needs a human who reads it and types
it. What stays in the tool result is everything a human needs in order to
DECIDE (the target, what would change, the plan lines, how to undo it).

Three KINDS today, and the configuration was always shaped so more could be
added without breaking it: `handelen.codekanaal` is always an object with a
`soort`, and `presenter_for()` below is THE one place that turns a `soort`
into a presenter. A later kind - a push to a phone, say - is one extra
branch there plus its own presenter; `_act()` in mcp_server.py never
changes, because it only ever calls the presenter.

* `venster` (`window_presenter`) - a MessageBox on the server's own screen.
  The model runs elsewhere (or at least in another process with no screen),
  so this is the demo default.
* `bestand` (`FileCodeChannel`) - the code in a file the operator names.
  Meant for practising and automation, where a driver reads the file. It is
  only as closed as the file is: an assistant that can read files on this
  machine can read this file too, which is why the documentation says
  plainly that this form is not for a session with file tools.
* `sso` (`SsoCodeChannel`) - a SEPARATE PROCESS, one line of
  JSON out and one line of JSON back, that delivers the code through an
  approval authority and - unlike the other two - can say WHO took delivery.
  `venster` and `bestand` show a code to whoever is at the screen or can read
  the file and cannot name that person; `bevestiger` is then `None` and every
  answer says so honestly. `sso` is the channel that can, which is what makes
  a later phase runner that refuses to start without an identified confirmer
  usable at all.

All three fail CLOSED: a channel that cannot show the code raises
`CodeChannelError`, and the caller (`mcp_server._act`) then burns the code it
had just issued and refuses the whole proposal. A code nobody saw must not
be a code that still works. There is never a silent fallback from one kind to
another.
"""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from nsmcp.collect import _stop_child_process
from nsmcp.confirm import TTL_S, _fingerprint, _normalize_code, marker_line
from nsmcp.powershell import PowerShellMissing, child_working_directory
from nsmcp.upgrade import _bounded_run_echo

# The one refusal an operator sees when a channel fails. Frozen text: it is
# product copy, pinned in tests/test_code_channel.py.
CHANNEL_FAILED = "bevestigingscode kon niet aan de beheerder getoond worden; er is niets gewijzigd"

TITLE = "Bevestigingscode"

# The three MessageBoxW flags, written out instead of imported: this product
# depends on no win32 package, and a bare 0x40000 in the call would say
# nothing. MB_OK is a single OK button; MB_TOPMOST and MB_SETFOREGROUND put
# the box in front of whatever the operator was looking at - a code that
# appears behind a full-screen window is a code that was not shown.
MB_OK = 0x00000000
MB_TOPMOST = 0x00040000
MB_SETFOREGROUND = 0x00010000

# How long the presenter waits to see whether MessageBoxW FAILED before it
# lets the tool call continue. The call itself does not return until the
# operator clicks OK, so waiting for its return value would block the tool
# for as long as the operator takes. A failing MessageBoxW (no interactive
# window station, no desktop) returns 0 immediately instead - so a short
# probe distinguishes "the box is up and waiting" from "there is no box",
# which is exactly the fail-closed measurement the design asks for, without
# ever waiting on a human.
SHOW_PROBE_S = 0.5

# How long the box stays up before it closes itself: exactly as long as the
# code in it is valid (confirm.TTL_S, in milliseconds).
#
# MessageBoxW does not return until someone clicks
# OK, so every proposal nobody dismissed left a thread standing for the life
# of the server process - and a window on the operator's screen showing a
# code that stopped working ten minutes ago. `MessageBoxTimeoutW` takes the
# same arguments as MessageBoxW plus a language id and this timeout, so the
# window lives exactly as long as what it shows and the thread ends by
# itself. Undocumented by its vendor but present in user32 on every current
# Windows; `window_presenter` therefore falls back to MessageBoxW when it is
# absent - a box that cannot count down is still a box, and refusing the
# whole proposal over a convenience would be fail-closed in the wrong place.
WINDOW_TIMEOUT_MS = TTL_S * 1000

# The neutral language id MessageBoxTimeoutW takes for its (unused) button
# captions: 0 = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL). The box shows one
# OK button, so this only says "do not pick a language of your own".
NEUTRAL_LANGUAGE_ID = 0


# The word each channel puts in the proposal's code-free line. Product copy,
# pinned in tests/test_handelen_zonder_code.py.
WINDOW_LABEL = "venster op de server"
FILE_LABEL = "bestand voor de beheerder"
SSO_LABEL = "goedkeuring via de beheerdersidentiteit"


# THE channel contract, stated ONCE, above both presenters it governs, so a
# new kind cannot guess it wrong and mcp_server.py's `code_presenter`
# docstring can point here instead of keeping its own copy (the two had
# drifted apart - five parameters there, six here):
#   presenter(tool, target, arguments, code, proposal_text, marker, section) -> None
# `section` is the allowlist section the code is bound to (the `doel` the
# call named). The write script forms its `target` label from its own facts,
# so two sections that allow the same action share one label; the section is
# what tells their proposals apart for the person who hands the code over.
# `_act()` has exactly one call site for this presenter, and
# that call always passes all seven positional arguments - so a parameter
# cannot be ABSENT from it: a presenter whose signature does not accept the
# marker or the section raises TypeError, and `_act()` treats every failure of this
# call as a channel failure - fail-closed, code burnt, nothing changed.
#
# That TypeError gate does NOT by itself prove the marker is ever RENDERED:
# a presenter that accepts `marker` (or `*args`/`**kwargs`) and
# silently drops it is structurally legal here - `tests/conftest.py` and
# `tests/test_mcp_server.py` both carry such a fake today, on purpose, for
# tests that do not care about the marker. What closes THAT gap is the
# test in `tests/test_code_channel.py`
# (`test_every_channel_renders_the_same_marker_text`, parametrized over
# `code_channel.KINDS` - see `test_every_channel_kind_is_covered_by_the_marker_test` next
# to it): a channel that renders the marker goes green, one that does not
# goes red BY NAME.


# No value drawn in the window is longer than this, and none carries a
# character the operator cannot see. A long value can push the code line out
# of view, and an invisible one can end the box before the code line is ever
# drawn - and the operator judges the proposal by what he sees here.
WINDOW_VALUE_CAP = 120

# The start of the one line the code stands on in the operator's text.
# `FileCodeChannel.spent()` reads it back to learn which code the file shows.
CODE_LINE_PREFIX = "bevestigingscode: "


class CodeChannelError(Exception):
    """The code could not be shown to the operator. Never silent."""


def _drawn(value) -> str:
    """One value as the window draws it: invisible characters removed,
    whitespace flattened, length capped.

    The window is a Win32 dialog, and `wintypes.LPCWSTR` marshals the message
    as a NUL-terminated wide string without objecting to an embedded NUL: one
    NUL in a drawn value ends the box there. Arguments are drawn ABOVE the
    code line, so that removes `bevestigingscode:` from the operator's screen
    entirely, and silently. Flattening whitespace alone does not close it -
    `str.split()` collapses the whitespace controls (line feed, carriage
    return, tab, the file/group/record/unit separators, NEL) and leaves every
    other C0 control (NUL, BEL, ESC, DEL) as well as the zero-width and bidi
    format characters that erase or reorder what is read.

    So everything that is neither printable nor whitespace is DROPPED: an
    invisible character may not stand in the value it hides in. What survives
    of the whitespace is flattened to single spaces, so no value can carry a
    line break of its own and fake a second dialog under the code. What is cut
    off is marked with " ...": a value silently shortened is a value the
    operator compares against the chat window believing he read it whole.
    """
    visible = "".join(ch for ch in str(value) if ch.isprintable() or ch.isspace())
    flat = " ".join(visible.split())
    return flat if len(flat) <= WINDOW_VALUE_CAP else flat[:WINDOW_VALUE_CAP] + " ..."


def _argument_lines(arguments: dict) -> list[str]:
    """One `<name>: <value>` line per action argument, sorted by name, every
    value drawn by `_drawn()`. THE rendering of the arguments a code is bound
    to: the window and the file channel show these lines under `wat:`, and
    the `sso` channel sends the same lines as its `argumenten` field. The
    allowlist section the code is also bound to is not an argument here and
    is not among these lines: every channel shows it on its own `sectie:`
    line (`sso`: its own `sectie` field)."""
    return [f"{name}: {_drawn(arguments[name])}" for name in sorted(arguments)]


def _message(tool: str, target: str, arguments: dict, code: str, marker: str, section: str) -> str:
    """The operator's own text. Dutch, ASCII, and everything needed to judge
    the proposal AGAINST the chat window: which tool, which target, which
    allowlist section, which arguments - so a code that belongs to a
    different action than the one on screen is visible as such before it is
    typed. The section stands on a line of its own under the target, always,
    also when it reads like the label: the label comes from the write script,
    and two sections that allow the same action get the same one.

    The marker sits on a line of ITS OWN, directly above the code. Not on the
    code line, for two reasons that both matter: that line is pinned product
    copy, and a test refuses anything code-shaped next to it. And it is
    rendered by `marker_line()` rather than formatted here, so the letter the
    operator reads in a window, in a file or through an approval is literally
    the same text - a third kind is no reason for a third form (design 3.4).
    """
    # SECURITY 21: values are capped and stripped of what cannot be seen
    # (`_drawn`), so no argument can push the code line out of sight.
    wat = "\n".join(f"  {line}" for line in _argument_lines(arguments))
    return (
        f"Handeling: {tool}\n"
        f"doel: {_drawn(target)}\n"
        f"sectie: {_drawn(section)}\n"
        f"wat:\n{wat}\n"
        "\n"
        f"{marker_line(marker)}\n"
        f"{CODE_LINE_PREFIX}{code}\n"
        "\n"
        "De code is tien minuten geldig en werkt een keer. Typ hem zelf in de chat; "
        "geef hem niet af als het voorstel op het scherm iets anders zegt dan hierboven."
    )


def _declare_box(function, *, counting: bool) -> None:
    """Declares argtypes/restype on the user32 entry point.

    Without it ctypes guesses how to marshal a pointer-sized argument. That
    happens to be right on 64-bit Windows today; a declaration is one line and
    removes the accident. `counting` distinguishes MessageBoxTimeoutW (two
    extra arguments) from plain MessageBoxW.

    `ctypes.wintypes` is imported HERE rather than at module level: it exists
    only on Windows, and the reading side of this product must stay importable
    on a machine without one. Everything that reaches this function has
    already found `ctypes.windll`, so it is on Windows by then.

    Both names come from the real `ctypes`, not from the module-level `ctypes`
    attribute: a declaration describes the WIN32 signature, and must say the
    same thing whether or not a caller replaced that attribute (the tests do,
    to stand in for `windll`).
    """
    from ctypes import c_int, wintypes

    base = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
    function.argtypes = base + ([wintypes.WORD, wintypes.DWORD] if counting else [])
    function.restype = c_int


def _show_box(windll, text: str) -> None:
    """Puts ONE box on the server's screen and measures whether it came up.

    The single place in this product that talks to user32: the code goes
    through it and so does a burn notice, so there is one set of flags, one
    choice between the counting and the plain MessageBox, and one probe to
    harden - not two.

    In a daemon thread, because the box does not return until it is dismissed
    and the tool call must not wait for a human. `SHOW_PROBE_S` above explains
    the short join: it catches the failure return (0) without ever waiting on
    the operator, and a box that is still up after the probe is a box that was
    shown.

    The box CLOSES ITSELF after `WINDOW_TIMEOUT_MS` - see that constant for
    the measurement behind it (a never-dismissed window used to keep both the
    thread and a dead code on screen for as long as the server lived).
    `MessageBoxTimeoutW` is used when user32 has it and plain `MessageBoxW`
    otherwise, so the fallback costs the countdown and never the channel.
    Either way `_declare_box` states the signature of the entry point that was
    found, instead of letting ctypes guess it (SECURITY 21).
    """
    # `getattr` with a default, not a try/except around the CALL: a real
    # ctypes WinDLL raises AttributeError when an export is missing, and that
    # error must be told apart from a failure INSIDE the box - the second one
    # is a channel failure and has to stay one.
    flags = MB_OK | MB_TOPMOST | MB_SETFOREGROUND
    counting_box = getattr(windll.user32, "MessageBoxTimeoutW", None)
    if counting_box is not None:
        _declare_box(counting_box, counting=True)

        def box(handle, text, title, flags):
            return counting_box(handle, text, title, flags, NEUTRAL_LANGUAGE_ID, WINDOW_TIMEOUT_MS)
    else:
        box = windll.user32.MessageBoxW
        _declare_box(box, counting=False)
    outcome: dict = {}

    def show() -> None:
        try:
            outcome["result"] = box(None, text, TITLE, flags)
        except Exception as exc:  # noqa: BLE001 - any failure here is a channel failure
            outcome["error"] = exc

    thread = threading.Thread(target=show, name="bevestigingscode-venster", daemon=True)
    thread.start()
    thread.join(SHOW_PROBE_S)
    if "error" in outcome:
        raise CodeChannelError(f"het venster kon niet getoond worden: {outcome['error']}")
    if outcome.get("result") == 0:
        raise CodeChannelError("het venster kon niet getoond worden (geen interactieve sessie op deze machine)")


# The Dutch sentence an operator reads when his proposal was guessed at. It
# names no code and no argument: it says the proposal is dead and why.
BURN_NOTICE = (
    "Een bevestigingscode is verbrand na vijf mislukte pogingen. Er is niets gewijzigd. "
    "Vraag een nieuw voorstel aan als u de handeling nog wilt uitvoeren."
)


def _window_notice(message: str) -> None:
    """The same box the code goes through, with a message instead of a code."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise CodeChannelError("dit platform heeft geen vensters (geen Windows)")
    _show_box(windll, message)


def send_notice(presenter, message: str) -> None:
    """Sends a message through the channel the operator got his code from.

    Best effort by design: a presenter without a notice route (a caller-supplied
    one, as the tests use) is not an error, and a channel that fails here must
    never turn a refusal into a crash. The refusal itself already happened.
    """
    route = getattr(presenter, "notice", None)
    if route is None:
        return
    try:
        route(message)
    except Exception:  # noqa: BLE001 - a notice is never fatal
        pass


def window_presenter(
    tool: str, target: str, arguments: dict, code: str, proposal_text: str, marker: str, section: str
) -> None:
    """Shows the code in a message box on the machine where THIS server runs.

    The box itself is `_show_box()` above - the one place that talks to
    user32, shared with the burn notice (SECURITY 10/21). What stays here
    is the OPERATOR TEXT (with the per-proposal marker) and the
    fail-closed refusal for a machine that has no windows at all.

    `proposal_text` is deliberately unused here - the proposal is already on
    the operator's screen in the chat; repeating a scrubbed script dump in a
    modal dialog would only push the code out of sight.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise CodeChannelError("dit platform heeft geen vensters (geen Windows); kies het bestandskanaal")
    _show_box(windll, _message(tool, target, arguments, code, marker, section))


window_presenter.label = WINDOW_LABEL
# This kind cannot name a confirmer. `mcp_server._act()` asks whichever
# presenter it holds for `bevestiger_for(code)` and for nothing else (a
# bare `.bevestiger` fallback was removed - a
# presenter carrying only that attribute answers for whichever proposal it
# delivered LAST, not for the code just redeemed). This kind offers neither,
# so it names no confirmer at all; the attribute below stays None, honestly,
# forever, and documents that for anyone reading this module.
window_presenter.bevestiger = None
window_presenter.notice = _window_notice


class FileCodeChannel:
    """Writes the code, with the proposal under it, to ONE file.

    Overwritten per proposal (never appended): a file with a history of codes
    is a file in which yesterday's code is indistinguishable from today's.
    UTF-8, and no ACL work - on Windows a file created under the operator's
    own profile inherits that profile's permissions, and this product does
    not pretend to harden a path the operator chose. That is documented
    rather than silently assumed (docs/klant/HANDLEIDING.md).
    """

    label = FILE_LABEL
    # Same reason as `window_presenter.bevestiger` above - this kind
    # cannot name a confirmer either, and `_act()` queries the attribute
    # uniformly across every kind.
    bevestiger = None

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        # One writer at a time on the file: a proposal is written from a
        # worker thread while `spent()` reads and rewrites the file on the
        # event loop, and a newer code landing between that read and that
        # write would otherwise still be wiped.
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def __call__(
        self,
        tool: str,
        target: str,
        arguments: dict,
        code: str,
        proposal_text: str,
        marker: str,
        section: str,
    ) -> None:
        body = f"{_message(tool, target, arguments, code, marker, section)}\n\n{proposal_text}\n"
        try:
            with self._lock:
                self._path.write_text(body, encoding="utf-8")
        except OSError as exc:
            raise CodeChannelError(f"kon het codebestand niet schrijven: {exc}") from None

    def notice(self, message: str) -> None:
        """Overwrites the file with a message. Overwrites rather than appends,
        for the same reason as the code itself: a file with a history is a file
        in which a dead code is indistinguishable from a live one."""
        try:
            with self._lock:
                self._path.write_text(f"{message}\n", encoding="utf-8")
        except OSError as exc:
            raise CodeChannelError(f"kon het codebestand niet schrijven: {exc}") from None

    def spent(self, code: str) -> None:
        """Called by `_act()` the moment the code is redeemed. Marks the
        file spent only while it still shows THIS code: several proposals
        can be outstanding at once, each with its own code, and the file
        shows the one written last. Spending an older code leaves a newer,
        still valid one in place instead of wiping it from view. The code
        arrives as the operator typed it, so both sides are folded the way
        the store folds them (`_normalize_code()`).

        Best effort: the action has already been authorized at this point,
        so a file that cannot be read or rewritten must not turn a
        successful handling into a crash. The code is spent in the store
        either way - what is left behind here is a dead code, not a usable
        one. The read, the comparison and the rewrite hold the file's lock
        together, so a proposal written meanwhile lands after them."""
        with self._lock:
            try:
                shown = self._path.read_text(encoding="utf-8")
            except (OSError, ValueError):
                return
            line = next((line for line in shown.splitlines() if line.startswith(CODE_LINE_PREFIX)), None)
            if line is None or _normalize_code(line.removeprefix(CODE_LINE_PREFIX)) != _normalize_code(code):
                return
            try:
                self._path.write_text("verbruikt\n", encoding="utf-8")
            except OSError:
                pass


# The presenter's answer is external-process output - untrusted input like
# any other (the hardening rule: never echoed raw). A UPN or an object id
# fits comfortably under this; a presenter that sends more is malformed, not
# verbose. Module-level, not class-level: it is a fact about the WIRE
# FORMAT, not about one channel instance.
#
# This caps the PARSED field, after `json.loads()` has already succeeded on
# whatever `communicate()` read - it does not, by itself, bound how many
# bytes `communicate()` reads off the pipe before that point. See the note
# at its call site in `__call__` for why that read is bounded in time
# (`self._wait_s`) and not in size.
_MAX_ANSWER_FIELD_LEN = 256

# The OUTGOING `voorstel` field's own bound,
# distinct from `_UNTRUSTED_ECHO_LIMIT` (200) that `_bounded_run_echo()`
# uses everywhere else. A real `onderhoud_upgrade_fase` proposal measured
# 748 characters - well past 200, and the 200-character cut used to land
# inside the proposal's own FIRST finding, before the phase being approved
# ever appeared. `voorstel` is one value in a JSON document a presenter
# PARSES, not a line printed to a terminal, so it can afford a much larger
# bound while still being a genuine bound - never unbounded, never raw.
_PROPOSAL_ECHO_LIMIT = 4000
_MAX_TARGET_CONTEXT_LEN = 256

# THE one canonical field set of the `sso` protocol's
# single outgoing JSON object (`SsoCodeChannel.__call__`, the `payload =
# json.dumps({...})` literal below) - pinned here, once, as a named
# constant instead of only existing implicitly as that dict literal's keys.
# `scripts/sso_presenter_windows.py` (the reference presenter) is
# deliberately stdlib-only (its own module docstring: it may import
# NOTHING from `nsmcp`, so it can be copied onto a machine that has only
# Python), so it cannot import this constant directly - it keeps its own
# `_PROTOCOL_FIELDS` copy instead. `tests/test_sso_presenter_windows.py`
# imports both this constant and that script's and asserts they name
# exactly the same fields, so the two copies cannot silently drift apart
# again - the same drift that left "fase" (added later) out of the
# presenter's own `_REQUIRED_FIELDS` while `SsoCodeChannel` had already
# been sending it for a while.
SSO_PROTOCOL_FIELDS = (
    "vingerafdruk",
    "code",
    "autoriteit",
    "aanduiding",
    "gereedschap",
    "doel",
    "sectie",
    "voorstel",
    "fase",
    "argumenten",
)

# The request fields a presenter mirrors back in its answer, after a positive
# human choice, exactly as it received them. A presenter written before the
# `sectie` field existed ignores that field, shows the code without the
# section and still answers `afgeleverd: true`; the mirror is how this channel
# tells such a presenter from one that read the section. `SsoCodeChannel`
# accepts a delivery only when every field here comes back equal to what it
# sent. The reference presenter keeps its own copy (`_ANSWER_MIRROR_FIELDS`,
# stdlib only); tests/test_sso_presenter_windows.py pins the two together.
SSO_ANSWER_MIRROR_FIELDS = ("sectie", "vingerafdruk")

# Why a delivery without an exact mirror is refused. Names neither the code
# nor the section, like every other reason this channel gives.
MIRROR_REFUSED = "de presenter spiegelt sectie en vingerafdruk niet terug: verouderde of onbekende presenter"

# The one fixed line `mcp_server` writes to its own log channel (stderr) when
# a delivery is refused for that reason: the caller reads only the generic
# channel-failure text, and the operator who must update the presenter needs
# to know it is the protocol. Fixed text - never the code, never the section.
OLD_PRESENTER_MARKER = "sso-presenter-protocol-oud"


class MirrorRefused(CodeChannelError):
    """A delivery refused because the answer does not mirror the section and
    fingerprint this channel sent - a presenter from before that protocol.
    Still a `CodeChannelError`: every caller that handles a failed channel
    handles this one the same way; `mcp_server` only adds the marker."""


def _clean_answer_field(value, veld: str) -> str:
    """Turns one field of a presenter's raw JSON answer into a safe string,
    or fails closed the same way a missing field already did.

    The type was already checked here
    (`isinstance`) but nothing capped the length or rejected control
    characters, and `mcp_server.py` interpolates this value straight into
    model-visible answer text (`f"bevestiger: {bevestiger}"`) - a presenter
    answering `"x\\nbevestiger: iemand anders"` could forge a line in that
    text, and one answering 50 kB could flood it. The hardening rule
    ("untrusted strings are never echoed raw") belongs on this channel
    boundary, not on the caller that merely formats what it was given.
    `str.isprintable()` rejects `\\n`, `\\r` and every other control or
    format character while leaving accented letters and other real text
    alone - it is False only for Unicode's "Other"/"Separator" categories
    (besides the ASCII space).
    """
    if not isinstance(value, str) or not value.strip():
        raise CodeChannelError(f"de presenter noemde geen {veld}")
    schoon = value.strip()
    if len(schoon) > _MAX_ANSWER_FIELD_LEN:
        raise CodeChannelError(f"de presenter gaf een {veld} terug die te lang is")
    if not schoon.isprintable():
        raise CodeChannelError(f"de presenter gaf een {veld} terug met stuurtekens erin")
    return schoon


class SsoCodeChannel:
    """The code goes to a channel that can also say WHO took delivery.

    A SEPARATE PROCESS, exactly like `collect` and `handelen`, and for the
    same reason: this product does not speak a network protocol itself, and
    an approval flow is a network protocol. The server writes ONE line of
    JSON to the presenter's stdin and reads ONE line of JSON back; what that
    presenter does in between - Entra, a push, a hardware token - is not this
    product's business and never becomes it, and this product opens no
    socket of its own for it either.

    Fail closed in every direction. A non-zero exit, an unreadable answer, a
    missing field, `afgeleverd: false`, an answer that does not mirror the
    section and fingerprint exactly (`SSO_ANSWER_MIRROR_FIELDS`), or the wait
    exceeded: all of them are `CodeChannelError`, and `mcp_server._act()`
    then burns the code it had just issued. A code nobody saw must not be a
    code that still works, and neither may a code shown without its section.
    There is NEVER a silent fallback to `venster` or `bestand`.

    The confirmer identity is an OPAQUE STRING (a UPN or an object id). It
    lands on `self.bevestiger` - the SAME attribute name `mcp_server._act()`
    used to read off whichever presenter it holds
    (`getattr(code_presenter, "bevestiger", None)`) and the same
    word `handelen.ActionResult.bevestiger` carries onward: one word for this
    concept everywhere, not "confirmer" here and "bevestiger" there. From
    there it travels to two places only: the action register and the tool
    answer. Not to the ledger by this class - the runner writes that itself
    from the same value (design 3.4).

    `self.bevestiger` alone is only correct
    for ONE outstanding proposal at a time - and this server holds a SINGLE
    `SsoCodeChannel` instance for its whole life (`mcp_server.py`'s
    `code_presenter=`). Multiple outstanding proposals are an acknowledged
    scenario (docs/klant/SECURITY.md: an older, un-redeemed code stays valid
    for `TTL_S`). Proposal A gets confirmer X, proposal B (a different code)
    then gets confirmer Y - a bare `.bevestiger` now answers Y for BOTH, so
    redeeming A would book action A on Y, or (if B's channel then failed and
    reset the attribute to `None`) report "niet vastgelegd" for A even
    though an identity did exist for it. `self.bevestiger` therefore stays,
    for single-call callers and the direct unit tests below, but the
    correct way to ask "who confirmed THIS code" is `bevestiger_for(code)`,
    which looks the confirmer up bound to the code it was delivered for
    (`self._per_code`), not to whichever proposal happened to run last.

    `bevestiger_for()`
    used to look `self._per_code` up with the code exactly as its caller
    passed it, while `_per_code` is keyed on the code AS ISSUED (upper case,
    unspaced - `confirm.ALPHABET`) and `ConfirmationStore.redeem()` folds
    its own input through `_normalize_code()` first (confirm.py:124-128 -
    every whitespace character removed, case folded to upper - built
    precisely because a human retypes a code sloppily). An operator who
    types `abc234` or `ABC 234` for an issued `ABC234` therefore redeemed
    correctly (the store normalizes) while `bevestiger_for("abc234")` missed
    the dict and returned `None` - a perfectly identified confirmer reported
    as unidentifiable. Both `_per_code`'s keys and `bevestiger_for()`'s
    lookup now go through the SAME `_normalize_code()` confirm.py itself
    asks callers to use, so ANY reader of this method - `_act()` today, a
    later phase runner that refuses to start on a channel it cannot
    identify - gets the right answer regardless of how the code reached it.
    """

    label = SSO_LABEL

    def __init__(self, presenter_path, authority: str, wait_s: int, now=time.monotonic) -> None:
        self._path = Path(presenter_path)
        self._authority = str(authority)
        self._wait_s = int(wait_s)
        self.bevestiger: str | None = None
        self.confirmed_at: str | None = None
        self._now = now
        # normalized code -> (bevestiger, expires_at) - normalized the SAME
        # way `ConfirmationStore._pending` is keyed (`_normalize_code()`), so
        # a code looked up here in whatever case or spacing the operator
        # retyped it still finds its entry. One entry per successfully
        # delivered proposal: `bevestiger_for()` pops its entry, and
        # `_sweep_expired()` (called on every delivery - the same "sweep on
        # both doors" pattern `ConfirmationStore._purge()` uses) drops
        # whatever nobody ever redeemed - so nothing here outlives either the
        # code it was bound to or its `TTL_S`, whichever comes first.
        self._per_code: dict[str, tuple[str, float]] = {}

    def _sweep_expired(self) -> None:
        """Drops every `_per_code` entry whose `TTL_S` has elapsed since
        delivery - mirrors `ConfirmationStore._purge()` for the same reason:
        an abandoned proposal (expired, mistyped, simply never redeemed)
        must not stay in memory for the life of the server process. Pure
        hygiene, never a security claim: `ConfirmationStore.redeem()`
        already refuses an expired code on its own clock, before
        `bevestiger_for()` is ever reached for it (`_act()` calls `redeem()`
        first) - a code this sweep has not yet reached could never have been
        read here successfully either."""
        now = self._now()
        verlopen = [code for code, (_, verloopt) in self._per_code.items() if now > verloopt]
        for code in verlopen:
            del self._per_code[code]

    def bevestiger_for(self, code: str) -> str | None:
        """The confirmer bound to THIS code - not to whichever proposal this
        instance last delivered. See the class docstring, findings 1 and the
        2nd-pass Important finding: `code` is folded through
        `_normalize_code()` before the lookup, the same folding
        `ConfirmationStore.redeem()` already applied to whatever the
        operator actually typed - so a sloppily retyped code still finds the
        entry it was delivered under."""
        entry = self._per_code.pop(_normalize_code(code), None)
        return entry[0] if entry is not None else None

    def __call__(
        self,
        tool: str,
        target: str,
        arguments: dict,
        code: str,
        proposal_text: str,
        marker: str,
        section: str,
    ) -> None:
        # Sweep BEFORE anything else, on every delivery: the same "sweep on
        # both doors" pattern `ConfirmationStore._purge()` uses on `issue()`,
        # so an abandoned proposal's entry does not outlive its `TTL_S`.
        self._sweep_expired()
        # Reset FIRST: whatever this call ends in, a stale bevestiger from an
        # earlier, unrelated proposal must never linger on this instance.
        self.bevestiger = None
        self.confirmed_at = None
        # Approval identity must not be rewritten by display sanitisation.
        # Reject invalid context before launching even a custom presenter.
        # The section is identity too: complete or refused, never cut.
        for value, field, limit in (
            (tool, "gereedschap", 4096),
            (target, "doel", _MAX_TARGET_CONTEXT_LEN),
            (section, "sectie", _MAX_TARGET_CONTEXT_LEN),
        ):
            if not isinstance(value, str) or not value.strip() or not value.isprintable() or len(value) > limit:
                raise CodeChannelError(f"ontbrekend of ongeldig veld: {field}")
        phase = arguments.get("fase", "")
        if tool == "onderhoud_upgrade_fase":
            valid_phase = isinstance(phase, str) and phase in {"R0", "R1", "R2", "R3", "R4", "R5", "R6"}
        else:
            valid_phase = isinstance(phase, str) and phase == ""
        if not valid_phase:
            raise CodeChannelError("ontbrekend of ongeldig veld: fase")
        # What the answer must mirror back, exactly (`SSO_ANSWER_MIRROR_FIELDS`).
        sent = {"sectie": section, "vingerafdruk": _fingerprint(tool, arguments, target, section)}
        payload = json.dumps(
            {
                # Covers the section as well: two sections with the same
                # label and the same arguments are two different requests.
                "vingerafdruk": sent["vingerafdruk"],
                "code": code,
                "autoriteit": self._authority,
                # Required by the reference presenter to distinguish an absent
                # upgrade phase from an ordinary action with no phase at all.
                "gereedschap": tool,
                # Design 3.7: the SAME marker text `venster` and `bestand`
                # render, so the presenter can show it too - a third kind is no
                # reason for a third form. `marker_line()` is the one rendering;
                # nothing here writes "voorstel " again.
                "aanduiding": marker_line(marker),
                # `venster` shows the operator the
                # TARGET and the `_message()`-rendered "doel:"/"wat:" lines
                # (never `proposal_text` itself - see `window_presenter`'s own
                # docstring); `bestand` shows the same plus the full
                # `proposal_text` appended below it. `sso` used to send
                # neither, so the one channel built to bind a human IDENTITY to
                # an action gave that human a code and a letter, and nothing
                # about what they were approving. Target identity is now
                # validated above and must remain complete. Proposal prose
                # still passes through the shared display sanitiser. The
                # confirmation CODE itself is not affected by this: it already
                # travelled in this payload by design (the `code` field
                # above), and nothing here adds a second copy of it anywhere.
                "doel": target,
                # The allowlist section the code is bound to, in a field of
                # its own and validated above like `doel`: the label comes
                # from the write script and is the same for two sections
                # that allow the same action, so without this field the
                # confirmer cannot tell their requests apart.
                "sectie": section,
                # `voorstel` gets its OWN, larger bound (`_PROPOSAL_ECHO_
                # LIMIT`, above) - a JSON payload value, not a terminal line.
                "voorstel": _bounded_run_echo(proposal_text, _PROPOSAL_ECHO_LIMIT),
                # A later fix gave `doel` its own field
                # precisely so it survives ANY cut of `voorstel`, whatever the
                # bound - `fase` is exactly as salient (the stated purpose:
                # "the confirmer can tell R1 from R3 from R4") and gets the
                # SAME treatment, not a bigger bound on `voorstel` alone. Only
                # `onderhoud_upgrade_fase` calls this channel with a `fase` key
                # in `arguments` at all; every other write tool's `arguments`
                # is a NITRO-object dict without one, so this is "" for them -
                # the same honest absence `bevestiger_for()` already returns
                # `None` for on a channel that cannot name a confirmer, not a
                # fabricated phase for a tool that has none.
                "fase": phase,
                # Every action argument the code is bound to (the allowlist
                # section, also bound, is not one of them - it has the
                # `sectie` field above), as the SAME lines
                # the window and the file channel show under `wat:`
                # (`_argument_lines()`): a list, one line per argument, in
                # its own field so no cut of `voorstel` can take one away.
                # For a phase that includes the snapshot reference and the
                # acceptance switches - the values a human must see before
                # the one channel that can start a phase delivers the code.
                "argumenten": _argument_lines(arguments),
            },
            ensure_ascii=True,
        )
        try:
            # 1.0.3: a `.py` presenter in isolated mode (`-I`) and every
            # presenter in the fixed working directory of all children, so
            # neither the server's working directory nor the presenter's own
            # directory lands on its module path.
            process = subprocess.Popen(
                [sys.executable, "-I", str(self._path)] if self._path.suffix == ".py" else [str(self._path)],
                cwd=child_working_directory(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, PowerShellMissing) as exc:
            raise CodeChannelError(f"de presenter kon niet gestart worden: {exc}") from None
        # `with process:` closes
        # stdin/stdout/stderr on EVERY exit from this block, including the
        # `TimeoutExpired` raise below. `_stop_child_process` ends the CHILD
        # but never closed this channel's own stdin handle - a bare
        # (non-`with`) `Popen` left that open until GC, which is exactly
        # what a non-deterministic `ResourceWarning: unclosed file` was
        # measuring.
        with process:
            try:
                # NOTE the actual shape of the boundary here: `communicate()` itself
                # bounds this presenter only in TIME (`self._wait_s`, below),
                # never in SIZE - it reads the whole answer into memory
                # before `_clean_answer_field()`'s `_MAX_ANSWER_FIELD_LEN`
                # ever gets a chance to apply. A presenter this product
                # itself was configured to run (`handelen.codekanaal.pad`,
                # the operator's own choice, the same trust boundary
                # `collect.py`/`handelen.py` already extend to every script
                # THEY run) is trusted to speak the tiny one-line protocol
                # documented above, not to flood its own stdout - and a slow
                # or hanging one is still what `self._wait_s` catches.
                # Bounding the READ itself by size, not just by time, would
                # mean reimplementing `communicate()`'s own deadlock-safe
                # write/read pairing by hand, in a fail-closed path already
                # hardened more than once below - a
                # real risk of a hang traded for a narrower memory ceiling on
                # a process this product started and already trusts.
                stdout, _stderr = process.communicate(payload + "\n", timeout=self._wait_s)
            except subprocess.TimeoutExpired:
                # A code nobody saw must not be a code that still works: end
                # the child (the same polite-then-hard termination
                # `collect`/`handelen` already use, not a second
                # implementation of it) before this raises. Exceeding
                # wachttijd_s is a NON-delivery, never an exception type of
                # its own - the caller learns nothing more from this than
                # from any other CodeChannelError.
                _stop_child_process(process, grace_s=2.0)
                raise CodeChannelError(
                    f"de wachttijd van {self._wait_s} seconden is verstreken zonder aflevering"
                ) from None
            if process.returncode != 0:
                raise CodeChannelError("de presenter meldde geen aflevering")
        # `stdout` is always a str here, never `None`: this `Popen` was
        # opened with `text=True` and a piped stdout, so `communicate()`
        # cannot return `None` for it. A stray `(stdout or "")` guard next
        # to a `stdout.strip()` on the SAME, UNGUARDED name used to raise
        # `AttributeError` before that guard could ever matter - dead
        # defence against a case that cannot
        # occur. `json.JSONDecodeError` is a `ValueError` subclass, so the
        # old exception tuple named the same thing twice; `ValueError`
        # alone already covers it.
        # The protocol answer is ONE line. A presenter that writes more - a
        # stray line, a second answer, an empty line - is not speaking it,
        # whatever its first line says; reading only that first line used to
        # accept such an answer as a delivery.
        if len(stdout.splitlines()) != 1:
            raise CodeChannelError("het antwoord van de presenter was niet precies een regel")
        try:
            antwoord = json.loads(stdout.splitlines()[0])
        except ValueError:
            raise CodeChannelError("het antwoord van de presenter was niet leesbaar") from None
        if not isinstance(antwoord, dict) or antwoord.get("afgeleverd") is not True:
            raise CodeChannelError("de presenter meldde geen aflevering")
        # A presenter from before the `sectie` field ignores it, shows the
        # code without the section and still reports a delivery. Only an
        # answer that mirrors the section and fingerprint this call sent,
        # exactly, shows the presenter read them; anything else - absent,
        # another request's, or merely similar - is no delivery.
        if any(antwoord.get(veld) != sent[veld] for veld in SSO_ANSWER_MIRROR_FIELDS):
            raise MirrorRefused(MIRROR_REFUSED)
        bevestiger = _clean_answer_field(antwoord.get("bevestiger"), "bevestiger")
        tijdstip = _clean_answer_field(antwoord.get("tijdstip"), "tijdstip")
        self.bevestiger = bevestiger
        self.confirmed_at = tijdstip
        self._per_code[_normalize_code(code)] = (bevestiger, self._now() + TTL_S)


# The kinds a configuration may name, in the order an error message lists
# them. THE list to extend when a new channel arrives.
KINDS = ("venster", "bestand", "sso")


class UnknownKind(Exception):
    """The configuration names a channel kind this version does not have."""


class MissingField(Exception):
    """The kind is known but a field it needs is absent or unusable."""


def presenter_for(kind: str, fields: dict):
    """THE seam: one `soort` in, one presenter out.

    Deliberately the only place in this product that knows which kinds
    exist. A future kind (a push notification, say) needs a branch here plus
    its own presenter - but do not read that as "and nothing else moves":
    `sso` needed its own twenty-line validation branch in
    `start.py._code_channel()` (a missing-field check, an https-only rule, a
    positive-int rule) and a new row in `start.py`'s `_CHANNEL_FIELDS`, not a
    validation frame that "stays as it is" (a prior version of this
    docstring made that claim while this very commit disproved it).
    `mcp_server._act()` is the one place that genuinely does
    not grow a branch per kind - it only ever calls the presenter and asks
    it for `bevestiger_for(code)` (`getattr(..., "bevestiger_for", None)`),
    without needing to know which kind it holds. `start.py` does the path discipline on the fields before calling
    this, because what a path may NOT be (inside a directory the product
    reads) is a fact about the configuration as a whole, not about this
    channel.

    Raises `UnknownKind` or `MissingField`; the caller turns those into its
    own configuration error, so this module carries no configuration
    vocabulary of its own. `sso`'s own check here is a BACKSTOP - `start.py`
    already validates all three of its fields before it ever calls this -
    kept so a caller that reaches this seam directly (as several tests do)
    fails the same honest way.
    """
    if kind == "venster":
        return window_presenter
    if kind == "bestand":
        path = fields.get("pad")
        if path is None:
            raise MissingField("pad")
        return FileCodeChannel(path)
    if kind == "sso":
        for veld in ("pad", "autoriteit", "wachttijd_s"):
            if fields.get(veld) in (None, ""):
                raise MissingField(veld)
        return SsoCodeChannel(fields["pad"], fields["autoriteit"], fields["wachttijd_s"])
    raise UnknownKind(kind)
