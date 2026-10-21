"""The reference presenter for the `sso` code channel.

Why this file exists: `nsmcp.code_channel.SsoCodeChannel` starts a
SEPARATE PROCESS - `[sys.executable, handelen.codekanaal.pad]` - writes ONE
line of JSON to its stdin and reads ONE line of JSON back. No real presenter
for that protocol existed before this task, only test stubs; without one,
`onderhoud_upgrade_fase` cannot start at all (the `venster` channel has no
`bevestiger` by design - it cannot say WHO confirmed). This script is that
reference implementation: "approval through the Windows identity of the
interactive session".

Deliberately standalone. `SsoCodeChannel` runs this as `[sys.executable,
pad]`, in its own process, so it never shares a Python import path with the
server - and it imports NOTHING from `nsmcp`, on purpose: only the standard
library (`ctypes`, `json`, `sys`, `datetime`), so this file can be copied
onto a machine that has Python and nothing else installed for it.

The protocol, read off stdin as one JSON object:
    {"vingerafdruk": "...", "code": "...", "autoriteit": "https://...",
     "aanduiding": "voorstel <letter>", "gereedschap": "onderhoud_upgrade_fase",
     "doel": "...", "sectie": "...", "fase": "R3", "voorstel": "...",
     "argumenten": ["<naam>: <waarde>", ...]}
(see `SsoCodeChannel.__call__` for the exact shape and
`start.py`'s `_code_channel()` for what `pad`/`autoriteit`/`wachttijd_s`
mean in the configuration: `autoriteit` is the https URL the approval comes
from, `wachttijd_s` is how long the caller waits before it kills this
process). `vingerafdruk` binds the request to one tool call, one set of
arguments, the shown target label and the allowlist section; this presenter
does not interpret it, it only mirrors it back unchanged after OK. `sectie`
is the allowlist section the code is bound to: the write script reports the
same `doel` label for two sections that allow the same action, so the
section is what tells their requests apart, and a request without it is
refused. Non-phase tools send an empty `fase`; phase requests require R0..R6.

The answer after OK mirrors `sectie` and `vingerafdruk` exactly as they were
received (`_ANSWER_MIRROR_FIELDS`). `SsoCodeChannel` accepts a delivery only
when both come back equal to what it sent: a presenter written before the
`sectie` field ignores that field, shows the code without the section and
still answers `afgeleverd: true` - without the mirror, that answer is no
delivery.

`code`, `aanduiding` and
`autoriteit` are ALL going to be shown to a human in the window text, so
`_read_request` requires each of them to be `str.isprintable()` (no NUL, no
line breaks, no other control/format character) and within a generous
length cap - and fails closed BEFORE any window is opened if they are not.
Before this, an embedded NUL was not rejected here; `argtypes` on
`MessageBoxW` then made ctypes silently truncate the text
AT that NUL instead of raising, so a human could see a window with the code
missing (or empty) and still click OK, and the click still delivered - the
one property this whole channel exists for. `vingerafdruk` is never shown,
so it is exempt from this check.

The window shows the marker (`aanduiding`), the target, the section, the phase, every
argument line (`argumenten`, one `<naam>: <waarde>` line per argument the
code is bound to), the bounded proposal, the sentence "goedkeuring namens
<autoriteit>" and the code, with OK and Cancel. OK writes exactly one
line of JSON to stdout - `{"afgeleverd": true, "sectie": "<as received>",
"vingerafdruk": "<as received>", "bevestiger": "<identity>",
"tijdstip": "<UTC ISO-8601, Z>"}` - and exits 0. `bevestiger` is the Windows
identity of the interactive session that showed the window
(`secur32.GetUserNameExW`, UPN first, `MACHINE\\gebruiker` as the fallback)
and is NEVER empty: a click this presenter cannot name a confirmer for is
not a delivery. That one line is
built as a single string and written with ONE `write()` call followed by
`flush()`, both inside the same `try`. If either fails, this still never
exits 0 - it fails closed exactly like any other channel failure (one fixed
reason on stderr, exit 1), even though some bytes of that line may by then
already be sitting in the stream. That is not a leak: `SsoCodeChannel`
(`code_channel.py`) checks `process.returncode != 0` BEFORE it ever reads
this process's stdout, so a receiver that follows the protocol only trusts
that line when this process exits 0, never merely because content is
present.

Every other outcome - Cancel, closing the window, no interactive desktop, a
request that cannot be read, a missing field, an identity that cannot be
established, or any other failure - fails CLOSED: no `afgeleverd: true`
line, ever, exit 1. A short, FIXED reason may go to stderr; it never
repeats the raw request line and never contains the code. The confirmation
code itself appears in exactly one place: the text shown in the window to
the human. Never in stdout outside that one success line's own JSON (which
does not carry it either), never in stderr, never in a file, never in a log
line, never in an argument.

There is no flag, environment variable or "test mode" that skips the
window or answers OK by itself - that is precisely the gap (a model that
confirms its own action) this channel exists to close. Tests instead
inject the window-showing and identity functions themselves: in-process,
as parameters of `main()`; and, for the one end-to-end test that proves the
real process boundary `SsoCodeChannel` opens, through a small wrapper
script that imports this module and replaces `_show_window`/`_get_identity`
as module attributes before calling `main()` with no arguments - which
works because `main()` looks those two names up at CALL time (a bare
reference in its body, never a default-parameter value bound at DEFINE
time), so a patch applied before the call is the patch `main()` sees.
"""

from __future__ import annotations

import ctypes
import json
import sys
from datetime import UTC, datetime

TITLE = "Bevestigingscode"

# MessageBoxW flags, written out rather than pulled from a win32 package:
# this script depends on nothing but the standard library. OK/Cancel (not a
# bare OK, unlike `code_channel.window_presenter`'s `venster` box) - this
# channel needs to know the human's answer, not merely that a box was
# shown. TOPMOST/SETFOREGROUND put it in front of whatever the operator was
# looking at, exactly like `window_presenter`'s box.
MB_OKCANCEL = 0x00000001
MB_TOPMOST = 0x00040000
MB_SETFOREGROUND = 0x00010000

# MessageBoxW's own return values for this button set.
IDOK = 1
IDCANCEL = 2

# `EXTENDED_NAME_FORMAT` values `GetUserNameExW` takes. UPN first ("who is
# this, portable across the domain"); `MACHINE\gebruiker` as the fallback
# on a machine with no UPN to give (a workgroup box, say) - still an
# identity, just a weaker one, and named honestly as such in this script's
# own docs, never silently upgraded to look like a UPN.
NAME_USER_PRINCIPAL = 8
NAME_SAM_COMPATIBLE = 2

# Measured: the full field set this protocol's ONE JSON object
# carries - pinned here as this file's own copy (this script imports
# nothing from `nsmcp`, see the module docstring, so it cannot import
# `nsmcp.code_channel.SSO_PROTOCOL_FIELDS` directly;
# tests/test_sso_presenter_windows.py pins the two together instead, so a
# future drift between them fails a test rather than surfacing live
# against a real presenter). "fase" is a REQUIRED key - always present -
# but, unlike the string fields, an EMPTY string is its valid value outside
# onderhoud_upgrade_fase, so `_REQUIRED_FIELDS` (the "must be a non-blank
# string" set the loop below enforces) is DERIVED from this one, minus
# "fase"; its own presence and value are validated separately, right after
# that loop. Measured: before this fix, "fase" (added later) was
# simply absent from `_REQUIRED_FIELDS` and from no other named set in
# this file either - its OWN validation still caught a missing value, but
# nothing here NAMED the fact that it belongs to this protocol's field set
# at all.
_PROTOCOL_FIELDS = (
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
# "argumenten" is required too, but it is a LIST of lines (one per argument
# the code is bound to, possibly none), so like "fase" it is validated on its
# own right after the string loop.
_REQUIRED_FIELDS = tuple(veld for veld in _PROTOCOL_FIELDS if veld not in ("fase", "argumenten"))

# The request fields the answer mirrors back after OK, exactly as received -
# this file's own copy of `nsmcp.code_channel.SSO_ANSWER_MIRROR_FIELDS`
# (stdlib only, see the module docstring); tests/test_sso_presenter_windows.py
# pins the two together. Both are required request fields, so they are always
# present and already validated by the time an answer is built.
_ANSWER_MIRROR_FIELDS = ("sectie", "vingerafdruk")

# MUST stay equal to `nsmcp.code_channel._MAX_ANSWER_FIELD_LEN` (256). This
# script cannot import that module - stdlib only, see the module docstring
# - so the value is duplicated here on purpose rather than silently; the
# test suite pins the two together (`tests/test_sso_presenter_windows.py`)
# so a change to one without the other fails the suite
# instead of surfacing live against a real presenter.
_MAX_BEVESTIGER_LEN = 256

# The ONE fixed, safe sentence `main()` writes to
# stderr for any failure it did not already give a specific reason for -
# never a Python traceback, which would print this file's own path, line
# numbers and source lines instead of a short, safe reason.
_UNEXPECTED_FAILURE_REASON = "onverwachte fout - geen aflevering"


class _ProtocolError(Exception):
    """The request on stdin could not be used. The message text is always
    one of a small set of FIXED, safe sentences - never the raw input line
    and never a field's value - so a caller that prints it can never leak
    the code, no matter which field was the problem."""


# These three fields all
# end up in the window text a human reads before clicking OK/Cancel, so they
# must be PRINTABLE - `str.isprintable()` rejects NUL, `\n`/`\r` and every
# other control or format character while leaving accented letters and
# other real text alone, the exact same rule
# `code_channel._clean_answer_field` already applies to the ANSWER side of
# this channel. `vingerafdruk` is never shown to a human, so it is exempt.
# Rejecting a control character here, before any window exists, closes two
# things at once: a NUL that `MessageBoxW`'s `argtypes`
# would otherwise silently truncate the visible text at (a window
# without the code that still delivers on OK), and a line break that could
# forge a second `bevestigingscode:` line or push the real `autoriteit`
# line out of view - the same forgery `confirm.marker_line()` already
# documents and closes on the PRODUCT's own marker text.
_PRINTABLE_FIELDS = ("code", "aanduiding", "autoriteit", "gereedschap", "doel", "sectie", "voorstel")

# A generous upper bound against a pathologically large value reaching the
# window-building code at all - well above anything a real value is (the
# display itself already truncates at `_MAX_DISPLAY_FIELD_LEN` = 200
# characters below), but bounded rather than unbounded.
_MAX_REQUEST_FIELD_LEN = 4096

# The server sends one line per argument: seven for a phase, at most three
# for any other write tool. A list longer than this cannot come from it, and
# is refused rather than drawn - enough lines would push the code off screen.
_MAX_ARGUMENT_LINES = 32


def _read_request(stream) -> dict:
    """Reads and validates the ONE line of JSON this protocol allows.

    Fails closed on anything that is not exactly what `SsoCodeChannel`
    sends: no input, input that is not one JSON object, a required field
    that is missing, not a string, or blank, or - for `code`, `aanduiding`
    and `autoriteit` - not printable or too long (see
    `_PRINTABLE_FIELDS` above). The field NAME may appear in the failure
    reason (it is not secret); the field's VALUE never does.
    """
    regel = stream.readline()
    if not regel or not regel.strip():
        raise _ProtocolError("geen invoer ontvangen")
    try:
        lading = json.loads(regel)
    except ValueError:
        raise _ProtocolError("de invoer was geen geldige JSON-regel") from None
    if not isinstance(lading, dict):
        raise _ProtocolError("de invoer had niet de verwachte vorm")
    for veld in _REQUIRED_FIELDS:
        waarde = lading.get(veld)
        if not isinstance(waarde, str) or not waarde.strip():
            raise _ProtocolError(f"ontbrekend of ongeldig veld: {veld}")
        if veld in _PRINTABLE_FIELDS:
            if len(waarde) > _MAX_REQUEST_FIELD_LEN:
                raise _ProtocolError(f"veld is te lang: {veld}")
            if not waarde.isprintable():
                raise _ProtocolError(f"veld bevat niet-printbare tekens: {veld}")
    # Target identity must remain fully visible; only the longer proposal is
    # display-capped. The explicit tool discriminates a missing phase from a
    # legitimate non-phase action. Never infer this from the proposal prose.
    if len(lading["doel"]) > 256:
        raise _ProtocolError("veld is te lang: doel")
    # The allowlist section is identity as well: shown whole or refused.
    if len(lading["sectie"]) > 256:
        raise _ProtocolError("veld is te lang: sectie")
    phase = lading.get("fase")
    if lading["gereedschap"] == "onderhoud_upgrade_fase":
        if not isinstance(phase, str) or phase not in {"R0", "R1", "R2", "R3", "R4", "R5", "R6"}:
            raise _ProtocolError("ontbrekend of ongeldig veld: fase")
    elif not isinstance(phase, str) or phase != "":
        raise _ProtocolError("ongeldig veld voor dit gereedschap: fase")
    # Every argument the code is bound to, shown to the human: a list of
    # printable lines, each within the same cap as a string field.
    regels = lading.get("argumenten")
    if not isinstance(regels, list) or len(regels) > _MAX_ARGUMENT_LINES:
        raise _ProtocolError("ontbrekend of ongeldig veld: argumenten")
    for regel in regels:
        if not isinstance(regel, str) or not regel.isprintable() or len(regel) > _MAX_REQUEST_FIELD_LEN:
            raise _ProtocolError("ontbrekend of ongeldig veld: argumenten")
    return lading


# `aanduiding`/`autoriteit` are product-/administrator-
# controlled, not attacker-controlled, but an oversized value (measured at
# 1 MB) pushes the code itself off screen - the one thing this box
# exists to show. Display-only cap; never applied to the code.
_MAX_DISPLAY_FIELD_LEN = 200


def _cap_for_display(value: str, limit: int = _MAX_DISPLAY_FIELD_LEN) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _format_message(
    aanduiding: str, autoriteit: str, code: str, doel: str, sectie: str, fase: str, voorstel: str, argumenten: list
) -> str:
    """Show validated target/section/phase and every argument line before
    the code, then the bound proposal prose. The section stands on a line of
    its own directly under the target, always. The argument lines stand apart from the
    proposal, so its 1000-character cut can never take one away; each line
    is capped for display like any other field (the server already caps
    every value at 120 characters, so a line it formed is never cut)."""
    aanduiding = _cap_for_display(aanduiding)
    autoriteit = _cap_for_display(autoriteit)
    phase_line = f"fase: {fase}\n" if fase else ""
    wat = "".join(f"  {_cap_for_display(regel)}\n" for regel in argumenten)
    proposal = _cap_for_display(voorstel, 1000)
    return (
        f"{aanduiding}\n"
        "\n"
        f"doel: {doel}\n"
        f"sectie: {sectie}\n"
        f"{phase_line}"
        "wat:\n"
        f"{wat}"
        "\n"
        f"{proposal}\n"
        "\n"
        f"goedkeuring namens {autoriteit}\n"
        "\n"
        f"bevestigingscode: {code}\n"
        "\n"
        "OK levert deze code af aan de aanvrager. Annuleren levert niets af "
        "en er verandert niets."
    )


def _show_window(text: str) -> int:
    """Shows the real MessageBoxW, OK/Cancel, topmost - and nothing else:
    no timeout, no countdown. Unlike `code_channel.window_presenter` (which
    must not block the tool call that shows it), THIS process exists only
    to show one box and wait for a human; `SsoCodeChannel`'s own
    `wachttijd_s` timeout already bounds that wait from the caller's side
    and kills this process if it is exceeded, so a second timer here would
    only duplicate that.

    Returns the raw MessageBoxW result: `IDOK`, `IDCANCEL`, or 0 - the same
    0 `window_presenter` treats as "no interactive session" (no window
    station, no desktop). Never raises for that case; only a genuinely
    unexpected failure propagates, and `main()` treats that the same way -
    fail closed, exit 1.

    `argtypes`/`restype` are set explicitly on the
    found `MessageBoxW` entry point, every call - this script is meant to be
    copied onto OTHER machines (a different Python build, a different ABI),
    and ctypes' default `restype` (`c_int`) happens to match `MessageBoxW`
    only by coincidence. The import is local, not a module attribute: a
    module-level `from ctypes import wintypes` would break the moment a test
    replaces `module.ctypes` itself (see `test_sso_presenter_windows.py`).

    A later fix: the import, the `argtypes`/`restype`
    setup and the call itself are all inside one try now - before this fix,
    only the import was unguarded; a failure there (or, in principle, in
    the attribute lookups or the call) escaped as its own exception type and
    only got `main()`'s GENERIC "onverwachte fout" reason, instead of the
    more precise "het venster kon niet getoond worden" `_run()` already
    gives for `OSError`. Any such failure is now folded into that same
    `OSError`, matching how `_query_user_name_ex` already treats failures in
    its own WinAPI setup as one outcome.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return 0
    try:
        from ctypes import c_int, wintypes

        message_box = windll.user32.MessageBoxW
        message_box.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
        message_box.restype = c_int
        flags = MB_OKCANCEL | MB_TOPMOST | MB_SETFOREGROUND
        return message_box(None, text, TITLE, flags)
    except OSError:
        raise
    except Exception as fout:
        # Fold any WinAPI setup/call failure into the same OSError `_run()`
        # already treats as "het venster kon niet getoond worden".
        raise OSError(str(fout)) from fout


def _query_user_name_ex(name_format: int) -> str | None:
    """One raw `secur32.GetUserNameExW(name_format)` call. `None` on any
    failure - no `windll`, the API call itself failing, or an empty result
    - never an exception: `_get_identity()` below tries the next format
    instead of ever raising past this point (the except
    clause is `Exception`, not only `OSError`, so an `AttributeError` from a
    missing export or a `ctypes.ArgumentError` from a bad argument fails
    this ONE lookup closed too, instead of escaping past `_get_identity()`).

    `argtypes`/`restype` are set explicitly on the
    found `GetUserNameExW` entry point (local import, same reasoning as
    `_show_window`'s) - `GetUserNameExW` returns `BOOLEAN` (one byte);
    ctypes' default `restype` (`c_int`, four bytes) reads register bits that
    are not guaranteed to be zeroed. `ctypes.pointer()` (not `byref()`) is
    used for the size out-parameter so a test can fake this entry point with
    a plain Python callable and still read/write through it.
    """
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    try:
        from ctypes import POINTER, c_int, wintypes

        secur32 = windll.secur32
        get_user_name_ex = secur32.GetUserNameExW
        get_user_name_ex.argtypes = [c_int, wintypes.LPWSTR, POINTER(wintypes.ULONG)]
        get_user_name_ex.restype = wintypes.BOOLEAN
        grootte = ctypes.c_ulong(0)
        grootte_ptr = ctypes.pointer(grootte)
        get_user_name_ex(name_format, None, grootte_ptr)
        if grootte.value == 0:
            return None
        buffer = ctypes.create_unicode_buffer(grootte.value)
        gelukt = get_user_name_ex(name_format, buffer, grootte_ptr)
        if not gelukt:
            return None
        # A later fix: reading `buffer.value` lives
        # INSIDE this try too now, not after it - it is the one remaining
        # notation in this function that touched the WinAPI result without
        # being covered by the "never raises past this point" promise this
        # docstring makes; a failure here now falls through to the next
        # identity format like every other failure in this function,
        # instead of escaping to `main()`'s generic catch-all.
        naam = buffer.value.strip()
    except Exception:  # noqa: BLE001 - any failure here is "this format did not resolve"; `_get_identity()` tries the next one, never raises
        return None
    return naam or None


def _get_identity() -> str | None:
    """The Windows identity of the interactive session that showed the
    window: the UPN when the machine has one, `MACHINE\\gebruiker`
    otherwise. `None` propagates as a channel failure - never a made-up or
    blank confirmer."""
    return _query_user_name_ex(NAME_USER_PRINCIPAL) or _query_user_name_ex(NAME_SAM_COMPATIBLE)


def _run(in_stream, out_stream, err_stream, toon_venster, haal_identiteit) -> int:
    """The actual protocol body, split out of `main()` so
    `main()` can wrap ONE call in ONE `except Exception` instead of guarding
    each step by hand. This function may still raise anything - a missing
    WinAPI export (`AttributeError`), an embedded NUL ctypes rejects
    (`ctypes.ArgumentError`), runaway JSON nesting (`RecursionError`), a
    decoding failure on real stdin bytes (`UnicodeError`) - every one of
    those is a channel failure, not a crash, and `main()` is the only place
    responsible for turning it into the one fixed, safe reason this script
    ever puts on stderr.
    """
    try:
        verzoek = _read_request(in_stream)
    except _ProtocolError as fout:
        print(str(fout), file=err_stream)
        return 1

    tekst = _format_message(
        verzoek["aanduiding"],
        verzoek["autoriteit"],
        verzoek["code"],
        verzoek["doel"],
        verzoek["sectie"],
        verzoek["fase"],
        verzoek["voorstel"],
        verzoek["argumenten"],
    )
    try:
        uitkomst = toon_venster(tekst)
    except OSError:
        print("het venster kon niet getoond worden", file=err_stream)
        return 1

    if uitkomst == 0:
        print(
            "geen interactieve sessie of geen Windows-vensters beschikbaar om de code te tonen",
            file=err_stream,
        )
        return 1
    if uitkomst != IDOK:
        print("niet bevestigd", file=err_stream)
        return 1

    identiteit = haal_identiteit()
    if not isinstance(identiteit, str) or not identiteit.strip():
        print("de identiteit van de sessie kon niet vastgesteld worden", file=err_stream)
        return 1
    schoon = identiteit.strip()
    # Begrenzen zoals de ontvanger hem accepteert
    # (`code_channel._clean_answer_field`) - niet leeg (hierboven al), alleen
    # printbare tekens (geen regeleinden/stuurtekens) en binnen de cap.
    # Zonder dit weigert de ontvanger een vervuild antwoord alsnog (fail
    # closed blijft overeind), maar de garantie hoort bij DIT bestand, de
    # referentie waar een derde presenter zich op baseert.
    if len(schoon) > _MAX_BEVESTIGER_LEN or not schoon.isprintable():
        print(
            "de identiteit van de sessie voldeed niet aan de eisen van het kanaal",
            file=err_stream,
        )
        return 1

    antwoord = {
        "afgeleverd": True,
        # Mirrored only here, after the human's OK: the channel accepts the
        # delivery only when these come back exactly as it sent them.
        **{veld: verzoek[veld] for veld in _ANSWER_MIRROR_FIELDS},
        "bevestiger": schoon,
        "tijdstip": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # The whole line is built as ONE string
    # first and then written with ONE `write()` call followed by `flush()`,
    # inside the SAME try - not the two separate `write()` calls this had
    # before (the JSON body, then a second call for the trailing newline),
    # where the FIRST could already succeed before the SECOND failed. If
    # writing or flushing still fails, that is a channel failure like any
    # other: a fixed reason on stderr, exit 1, NEVER exit 0 - see the module
    # docstring for why a receiver that follows the protocol stays safe
    # even if bytes of this line reached the stream before the failure.
    regel = json.dumps(antwoord, ensure_ascii=True) + "\n"
    try:
        out_stream.write(regel)
        out_stream.flush()
    except Exception:  # noqa: BLE001 - write/flush can fail for any reason; fail closed regardless of the exception type
        print("de aflevering kon niet volledig geschreven worden", file=err_stream)
        return 1
    return 0


def main(stdin=None, stdout=None, stderr=None, show_window=None, get_identity=None) -> int:
    """The entrypoint. `stdin`/`stdout`/`stderr` default to the real
    streams; `show_window`/`get_identity` default to the module-level
    functions above, looked up here BY NAME (not as a default parameter
    value) so a caller that patches `_show_window`/`_get_identity` on this
    module before calling `main()` with no arguments is honoured too - see
    the module docstring for why that matters to the tests.

    Everything below the stream/callable setup
    runs inside ONE `except Exception`. Before this fix, only `_ProtocolError`
    (from reading the request) and `OSError` (from showing the window) were
    caught by name - any OTHER exception class (`AttributeError` from a
    missing WinAPI export, `ctypes.ArgumentError` from an embedded NUL,
    `RecursionError` from pathological JSON nesting, `UnicodeError` from a
    real stdin decoding failure) escaped uncaught. Fail-closed still held
    (an uncaught exception still exits 1 and never prints the code), but
    only because that is Python's own default handling of an uncaught
    exception - which also prints a full traceback with this file's path
    and source lines to stderr, breaking the "korte, VASTE reden" promise
    this module's docstring makes. This is that promise, enforced in code.

    The except clause also names
    `KeyboardInterrupt` explicitly - it is a `BaseException`, not an
    `Exception`, so a Ctrl+C arriving while `_run()` is blocked in the real
    `MessageBoxW` call used to escape this `try` entirely and print
    Python's own full traceback (this file's path and source lines) instead
    of the one fixed reason, even though fail-closed itself never broke
    (an uncaught exception still exits non-zero and never prints the code).
    `SystemExit`/`GeneratorExit` are deliberately NOT added: nothing in this
    module calls `sys.exit()` before this point, so there is nothing of
    that kind to let through, and catching them here would only hide a
    genuine interpreter-level exit signal.

    The `print()` that reports the fixed
    reason is itself wrapped - a broken `err_stream` (a closed pipe, say)
    used to let ITS OWN failure escape `main()` uncaught, defeating fail
    closed at the very last step. Best-effort only: if stderr cannot be
    written to either, there is nothing left to do but still return 1.
    """
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    err_stream = stderr if stderr is not None else sys.stderr
    toon_venster = show_window if show_window is not None else _show_window
    haal_identiteit = get_identity if get_identity is not None else _get_identity

    try:
        return _run(in_stream, out_stream, err_stream, toon_venster, haal_identiteit)
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - any unexpected failure here is a channel failure; fail closed with the one fixed reason, never a traceback
        try:
            print(_UNEXPECTED_FAILURE_REASON, file=err_stream)
        except Exception:  # noqa: BLE001, S110 - best-effort; still fail closed via the return below even if stderr itself is broken too
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
