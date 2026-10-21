# tests/test_sso_presenter_windows.py
"""The sso channel's reference presenter (scripts/sso_presenter_windows.py).

`code_channel.SsoCodeChannel` starts this script as a SEPARATE PROCESS,
writes ONE line of JSON to its stdin and reads ONE line of JSON back (see
`nsmcp.code_channel.SsoCodeChannel.__call__`). No real presenter for this
channel existed before this task; only test stubs did. This file measures
the reference presenter against that same protocol, plus the three
invariants that are binding for this channel:

1. the confirmation code never appears in a tool result, a log, stderr, an
   argument or a file - only in the window shown to a human;
2. nothing is confirmed without a human (no flag, no env var, no "test
   mode" skips the window);
3. the product's working name never appears as a contiguous literal in
   `src/`, `tests/` or `scripts/`.

The tests never call the real MessageBoxW: CI runs without a desktop, so
`main()` takes the window-showing and identity functions as parameters
(tests 1-4, in-process) and the end-to-end test (5) writes its own wrapper
script that imports the module and replaces those same functions as module
attributes before calling `main()` - proven against the real process
boundary `SsoCodeChannel` opens, exactly like the other two channels'
fakes in `tests/test_code_channel.py`.
"""

from __future__ import annotations

import ctypes
import importlib.util
import io
import json
import types
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

import pytest

from nsmcp import code_channel

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
SCRIPT_PATH = SCRIPTS_DIR / "sso_presenter_windows.py"

# A recognizable, code-shaped planted value - never a real confirmation
# code, so a hit anywhere in stdout/stderr can only be this test's own
# plant, not a coincidence.
PLANTED_CODE = "ZQ7F2K"

IDENTITY = "GJKDEMO\\operator"


def _load_module():
    """Loads the script as a module IN-PROCESS. Deliberately not an
    `import` of a package member: the script has no package, must run
    standalone with only the standard library (it may not import from
    `nsmcp`), and this loader proves that by never
    touching `sys.path` to make it importable as one."""
    spec = importlib.util.spec_from_file_location("sso_presenter_windows_under_test", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request_line(code: str = PLANTED_CODE, **overrides) -> str:
    payload = {
        "vingerafdruk": "abc123fingerprint",
        "code": code,
        "autoriteit": "https://voorbeeld.invalid/goedkeuren",
        "aanduiding": "voorstel A",
        "gereedschap": "certificaat_vervangen",
        "doel": "[TARGET] doos",
        "sectie": "lab-a",
        "fase": "",
        "voorstel": "Vervang het bevestigde certificaat.",
        "argumenten": ["dienst: lb_vs_a", "nieuwcert: cert-2027"],
    }
    payload.update(overrides)
    return json.dumps(payload) + "\n"


def _run(module, invoer: str, *, show_window, get_identity):
    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(invoer),
        stdout=out,
        stderr=err,
        show_window=show_window,
        get_identity=get_identity,
    )
    return exit_code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# 1. protocol: valid input + OK -> exactly one JSON line, afgeleverd true,
#    bevestiger equals the injected identity, tijdstip parseable; exit 0.
# ---------------------------------------------------------------------------


def test_protocol_ok_delivers_exactly_one_json_line_with_the_injected_identity():
    module = _load_module()
    exit_code, out, err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 0
    regels = out.splitlines()
    assert len(regels) == 1
    antwoord = json.loads(regels[0])
    assert antwoord["afgeleverd"] is True
    assert antwoord["bevestiger"] == IDENTITY
    assert antwoord["tijdstip"].endswith("Z")
    # parseable ("tijdstip parsebaar") - Python 3.11+
    # `fromisoformat` accepts the "Z" suffix directly.
    datetime.fromisoformat(antwoord["tijdstip"])
    assert err == ""


def test_ok_mirrors_the_received_section_and_fingerprint_exactly():
    """After OK the answer carries the section and the fingerprint exactly
    as this presenter received them - the proof `SsoCodeChannel` requires
    that the presenter read the section field at all. Values other than the
    defaults of `_request_line()`, so a constant in the presenter cannot
    pass this."""
    module = _load_module()
    sectie = "lab-oost-2"
    vingerafdruk = "0f" * 32
    exit_code, out, _err = _run(
        module,
        _request_line(sectie=sectie, vingerafdruk=vingerafdruk),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 0
    antwoord = json.loads(out)
    assert antwoord["sectie"] == sectie
    assert antwoord["vingerafdruk"] == vingerafdruk
    assert set(antwoord) == {"afgeleverd", "bevestiger", "tijdstip", *code_channel.SSO_ANSWER_MIRROR_FIELDS}
    assert PLANTED_CODE not in out


def test_ok_shows_the_marker_the_authority_and_the_code_in_the_window_text():
    """The window text is the one place the code MAY appear (invariant 1) -
    measured here by capturing what `show_window` actually received."""
    module = _load_module()
    seen = {}

    def capture(text):
        seen["text"] = text
        return module.IDOK

    _run(module, _request_line(), show_window=capture, get_identity=lambda: IDENTITY)
    text = seen["text"]
    assert "voorstel A" in text
    assert "https://voorbeeld.invalid/goedkeuren" in text
    assert PLANTED_CODE in text


# ---------------------------------------------------------------------------
# 2. Annuleren -> geen afgeleverd: true op stdout, exit 1.
# ---------------------------------------------------------------------------


def test_cancel_delivers_nothing_and_exits_1():
    module = _load_module()
    exit_code, out, _err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDCANCEL,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out == ""


def test_no_interactive_desktop_delivers_nothing_and_exits_1():
    """`show_window` returning 0 is MessageBoxW's own shape for "could not
    be shown" (no window station, no desktop) - the same failure
    `code_channel.window_presenter` treats as a channel failure."""
    module = _load_module()
    exit_code, out, _err = _run(
        module,
        _request_line(),
        show_window=lambda text: 0,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out == ""


def test_no_identity_delivers_nothing_and_exits_1():
    """`bevestiger` mag nooit leeg zijn - kan de identiteit niet vastgesteld
    worden, dan wordt er niets afgeleverd, ook al klikte de mens OK."""
    module = _load_module()
    exit_code, out, _err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: None,
    )
    assert exit_code == 1
    assert out == ""


# ---------------------------------------------------------------------------
# 3. ontbrekend veld / geen JSON / lege invoer -> exit 1, code niet in
#    stderr.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "invoer",
    [
        "",
        "   \n",
        "dit is geen json {{{",
        json.dumps(
            {
                # vingerafdruk missing
                "code": PLANTED_CODE,
                "autoriteit": "https://x.invalid",
                "aanduiding": "voorstel A",
            }
        ),
        json.dumps({"vingerafdruk": "f", "code": "", "autoriteit": "https://x", "aanduiding": "voorstel A"}),
        json.dumps([1, 2, 3]),
    ],
)
def test_bad_or_incomplete_input_exits_1_without_leaking_the_code(invoer):
    module = _load_module()
    exit_code, out, err = _run(
        module,
        invoer,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out == ""
    assert PLANTED_CODE not in err
    assert PLANTED_CODE not in out


# ---------------------------------------------------------------------------
# 4. de code staat nooit in stdout of stderr - ook in het foutpad.
# ---------------------------------------------------------------------------


def test_the_code_never_reaches_stdout_or_stderr_on_the_ok_path():
    module = _load_module()
    _exit_code, out, err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_the_code_never_reaches_stdout_or_stderr_on_the_cancel_path():
    module = _load_module()
    _exit_code, out, err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDCANCEL,
        get_identity=lambda: IDENTITY,
    )
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_the_code_never_reaches_stdout_or_stderr_when_identity_fails():
    module = _load_module()
    _exit_code, out, err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: None,
    )
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


# ---------------------------------------------------------------------------
# 5. end-to-end via SsoCodeChannel zelf, met een wrapper die de module
#    importeert en de venster-/identiteitsfunctie vervangt voordat hij
#    main() aanroept - de echte procesgrens, nooit de echte MessageBoxW.
# ---------------------------------------------------------------------------

_WRAPPER = """\
import sys
sys.path.insert(0, {scripts_dir!r})
import sso_presenter_windows as sp

sp._show_window = lambda text: {result}
sp._get_identity = lambda: {identity!r}
sys.exit(sp.main())
"""


def _write_wrapper(tmp_path: Path, result: str, identity) -> Path:
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(
        _WRAPPER.format(scripts_dir=str(SCRIPTS_DIR), result=result, identity=identity),
        encoding="utf-8",
    )
    return wrapper


def test_end_to_end_ok_via_sso_code_channel_names_the_injected_confirmer(tmp_path):
    wrapper = _write_wrapper(tmp_path, "sp.IDOK", IDENTITY)
    kanaal = code_channel.SsoCodeChannel(wrapper, "https://voorbeeld.invalid/goedkeuren", 15)
    kanaal("certificaat_vervangen", "[TARGET] doos", {"dienst": "lb_vs_a"}, "ABC234", "voorstel", "A", "lab")
    assert kanaal.bevestiger_for("ABC234") == IDENTITY


def test_end_to_end_cancel_via_sso_code_channel_gives_no_delivery(tmp_path):
    wrapper = _write_wrapper(tmp_path, "sp.IDCANCEL", IDENTITY)
    kanaal = code_channel.SsoCodeChannel(wrapper, "https://voorbeeld.invalid/goedkeuren", 15)
    with pytest.raises(code_channel.CodeChannelError, match="geen aflevering"):
        kanaal(
            "certificaat_vervangen",
            "[TARGET] doos",
            {"dienst": "lb_vs_a"},
            "ABC234",
            "voorstel",
            "A",
            "lab",
        )
    assert kanaal.bevestiger is None


# ---------------------------------------------------------------------------
# 6. naamneutraliteit: `tests/test_product_surface.py`'s guard scans only
#    `src/` and `tests/` - this checks `scripts/` itself, with the working
#    name from the needle list outside the tree (tests/private_needles.py).
# ---------------------------------------------------------------------------


def test_scripts_directory_has_no_product_name_literal():
    from private_needles import needles_or_skip

    verboden = [name.lower() for name in needles_or_skip("werknaam")]
    hits = []
    for pad in SCRIPTS_DIR.rglob("*"):
        if not pad.is_file():
            continue
        try:
            tekst = pad.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, regel in enumerate(tekst.splitlines(), 1):
            if any(naam in regel.lower() for naam in verboden):
                hits.append(f"{pad}:{n}")
    assert hits == [], f"productnaam gevonden in scripts/: {hits}"


# ---------------------------------------------------------------------------
# 7. Elke onverwachte exceptie rond invoer, venster of
#    identiteit eindigt in de EEN vaste, korte reden op stderr - nooit een
#    traceback, nooit de invoer, nooit de code - en exit 1.
# ---------------------------------------------------------------------------


class _RaisingStream:
    """A stdin stand-in whose `readline()` raises a given exception - proves
    `main()` fails closed with the ONE fixed reason on exception classes
    `_read_request` itself never names by type (a missing WinAPI export, an
    embedded NUL, runaway JSON nesting, a decoding failure on real stdin
    bytes - the four classes named explicitly: AttributeError,
    ctypes.ArgumentError, RecursionError, UnicodeError)."""

    def __init__(self, exc: BaseException):
        self._exc = exc

    def readline(self):
        raise self._exc


_UNEXPECTED_EXCEPTIONS = [
    AttributeError("'WinDLL' object has no attribute 'MessageBoxW'"),
    ctypes.ArgumentError("argument 1: ValueError: embedded null character"),
    RecursionError("maximum recursion depth exceeded"),
    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
]


@pytest.mark.parametrize("exc", _UNEXPECTED_EXCEPTIONS)
def test_unexpected_exception_reading_input_fails_closed_with_the_fixed_reason(exc):
    module = _load_module()
    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=_RaisingStream(exc),
        stdout=out,
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert err.getvalue() == module._UNEXPECTED_FAILURE_REASON + "\n"
    assert PLANTED_CODE not in err.getvalue()


@pytest.mark.parametrize("exc", _UNEXPECTED_EXCEPTIONS)
def test_unexpected_exception_from_show_window_fails_closed_with_the_fixed_reason(exc):
    module = _load_module()

    def boom(text):
        raise exc

    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=out,
        stderr=err,
        show_window=boom,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert err.getvalue() == module._UNEXPECTED_FAILURE_REASON + "\n"
    assert PLANTED_CODE not in err.getvalue()


@pytest.mark.parametrize("exc", _UNEXPECTED_EXCEPTIONS)
def test_unexpected_exception_from_get_identity_fails_closed_with_the_fixed_reason(exc):
    module = _load_module()

    def boom():
        raise exc

    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=out,
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=boom,
    )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert err.getvalue() == module._UNEXPECTED_FAILURE_REASON + "\n"
    assert PLANTED_CODE not in err.getvalue()


def test_real_deeply_nested_json_fails_closed_with_the_fixed_reason_not_a_traceback():
    """The actual trigger measured: a pathological
    depth through the real `_read_request`/`json.loads` path, not an
    injected stand-in."""
    module = _load_module()
    diep = "[" * 200_000 + "]" * 200_000 + "\n"
    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(diep),
        stdout=out,
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert err.getvalue() == module._UNEXPECTED_FAILURE_REASON + "\n"
    # a raw traceback would carry this file's own path and "File " lines
    assert "Traceback" not in err.getvalue()
    assert __file__ not in err.getvalue()


# ---------------------------------------------------------------------------
# 8. Bevestiger begrensd zoals code_channel._clean_answer_field
#    hem accepteert - niet leeg, printbaar, binnen de lengte-cap.
# ---------------------------------------------------------------------------


def test_bevestiger_length_cap_matches_code_channel_clean_answer_field():
    """Dit script mag `code_channel` niet importeren (zie de moduledocstring:
    alleen stdlib), dus de cap is hier gedupliceerd - deze test pint de twee
    waarden aan elkaar zodat een wijziging aan de ene kant zonder de andere
    hier faalt, in plaats van pas live tegen een echte presenter."""
    module = _load_module()
    assert module._MAX_BEVESTIGER_LEN == code_channel._MAX_ANSWER_FIELD_LEN


def test_protocol_field_set_matches_the_sso_channels_own_payload():
    """Design row A6: `code_channel.SSO_PROTOCOL_FIELDS` is the one
    canonical field set the `sso` protocol's outgoing JSON object carries.
    This script cannot import it (stdlib-only, see the module docstring),
    so it keeps its own `_PROTOCOL_FIELDS` copy - this test pins the two
    together, the same way the two tests above/below already pin the
    bevestiger cap and printability rule, so a future field added on one
    side and forgotten on the other fails a test instead of surfacing live
    against a real presenter. Measured: "fase" (added later) was
    missing from this script's own `_REQUIRED_FIELDS` while `SsoCodeChannel`
    had already been sending it - `_REQUIRED_FIELDS` is now DERIVED from
    `_PROTOCOL_FIELDS`, so that specific drift cannot recur."""
    module = _load_module()
    assert set(module._PROTOCOL_FIELDS) == set(code_channel.SSO_PROTOCOL_FIELDS)
    assert len(module._PROTOCOL_FIELDS) == len(code_channel.SSO_PROTOCOL_FIELDS)
    # "fase" is a REQUIRED key (always present) but, unlike the other
    # seven, an EMPTY string is its valid value outside
    # onderhoud_upgrade_fase - so it is validated separately (right after
    # the `_REQUIRED_FIELDS` loop in `_read_request`), not folded into the
    # "must be non-blank" set. "argumenten" is required as well but is a
    # list of lines, validated on its own after that loop too
    # (tests/test_sso_presenter_context.py measures a missing one).
    assert set(module._REQUIRED_FIELDS) == set(code_channel.SSO_PROTOCOL_FIELDS) - {"fase", "argumenten"}


def test_answer_mirror_fields_match_the_sso_channels_own_check():
    """The fields the presenter mirrors back and the fields the channel
    compares are two copies of one list (stdlib-only script, see the module
    docstring); pinned together so neither side can drop one silently."""
    module = _load_module()
    assert module._ANSWER_MIRROR_FIELDS == code_channel.SSO_ANSWER_MIRROR_FIELDS
    assert set(code_channel.SSO_ANSWER_MIRROR_FIELDS) == {"sectie", "vingerafdruk"}
    assert set(code_channel.SSO_ANSWER_MIRROR_FIELDS) <= set(code_channel.SSO_PROTOCOL_FIELDS)


def test_bevestiger_with_control_characters_is_not_delivered():
    module = _load_module()
    exit_code, out, err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: "GJK\nbevestiger: iemand anders",
    )
    assert exit_code == 1
    assert out == ""
    assert "iemand anders" not in err


def test_bevestiger_over_the_length_cap_is_not_delivered():
    module = _load_module()
    exit_code, out, _err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: "x" * (module._MAX_BEVESTIGER_LEN + 1),
    )
    assert exit_code == 1
    assert out == ""


def test_bevestiger_at_exactly_the_cap_is_still_delivered():
    """Grensgeval: de cap zelf mag niet afgewezen worden, alleen erover.
    Leest de cap nu van `module._MAX_BEVESTIGER_LEN`
    in plaats van een hardgecodeerde 256 - verhoogt iemand de cap, dan
    blijft deze grenstest de ECHTE grens meten in plaats van niets meer."""
    module = _load_module()
    identiteit = "x" * module._MAX_BEVESTIGER_LEN
    exit_code, out, _err = _run(
        module,
        _request_line(),
        show_window=lambda text: module.IDOK,
        get_identity=lambda: identiteit,
    )
    assert exit_code == 0
    antwoord = json.loads(out)
    assert antwoord["bevestiger"] == identiteit


# ---------------------------------------------------------------------------
# 9. Argtypes/restype op MessageBoxW en GetUserNameExW, en
#    de aanroeper past de declaratie ook echt toe op de gevonden ingang.
# ---------------------------------------------------------------------------


# Every test below patches
# `ctypes.windll` on the REAL, global `ctypes` module (`module.ctypes` IS
# that module - the script never copies it). `monkeypatch.setattr` requires
# the attribute to already exist, so on a machine with no `ctypes.windll`
# (any non-Windows platform) these used to fail with a bare `AttributeError`
# instead of skipping - the wrong reason to fail for a product layer that
# documents itself as Windows-only. This marker makes that an explicit skip.
_WINDOWS_ONLY = pytest.mark.skipif(
    not hasattr(ctypes, "windll"),
    reason="Windows-only: ctypes.windll bestaat niet op dit platform",
)


class _FakeWinapiFunc:
    """Stand-in voor een ctypes-foreign-function-object: net als het echte
    object accepteert het `.argtypes`/`.restype`-toekenningen (gewoon
    attributen) en registreert elke aanroep, zodat een test kan bewijzen dat
    de declaratie ook echt op DEZE ingang is toegepast - niet ergens
    anders, en niet alleen in een comment."""

    def __init__(self, handler):
        self.argtypes = None
        self.restype = None
        self._handler = handler
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self._handler(*args)


@_WINDOWS_ONLY
def test_show_window_sets_argtypes_and_restype_on_message_box_w(monkeypatch):
    fake_box = _FakeWinapiFunc(lambda *_args: 1)
    fake_user32 = types.SimpleNamespace(MessageBoxW=fake_box)
    fake_windll = types.SimpleNamespace(user32=fake_user32)
    module = _load_module()
    monkeypatch.setattr(module.ctypes, "windll", fake_windll)

    result = module._show_window("tekst")

    assert result == 1
    assert len(fake_box.calls) == 1
    assert fake_box.argtypes == [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.UINT,
    ]
    assert fake_box.restype is ctypes.c_int


@_WINDOWS_ONLY
def test_query_user_name_ex_sets_argtypes_and_restype_on_get_user_name_ex_w(monkeypatch):
    # Matches the two-call pattern measured live: call 1 reports
    # the required size (including the trailing NUL), call 2 fills the
    # buffer and returns a truthy BOOLEAN.
    def handler(_name_format, buffer, grootte_ptr):
        if buffer is None:
            grootte_ptr.contents.value = 17
            return 0
        buffer.value = "WERKPLEK-01\\demo"
        return 1

    fake_fn = _FakeWinapiFunc(handler)
    fake_secur32 = types.SimpleNamespace(GetUserNameExW=fake_fn)
    fake_windll = types.SimpleNamespace(secur32=fake_secur32)
    module = _load_module()
    monkeypatch.setattr(module.ctypes, "windll", fake_windll)

    naam = module._query_user_name_ex(module.NAME_SAM_COMPATIBLE)

    assert naam == "WERKPLEK-01\\demo"
    assert len(fake_fn.calls) == 2
    assert fake_fn.argtypes == [ctypes.c_int, wintypes.LPWSTR, ctypes.POINTER(wintypes.ULONG)]
    assert fake_fn.restype is wintypes.BOOLEAN


# ---------------------------------------------------------------------------
# 10. `code`, `aanduiding`
#     en `autoriteit` moeten printbaar zijn VOORDAT er een venster komt.
#     Voor de fix kapte ctypes' `LPCWSTR`-conversie een ingebedde NUL stil
#     af - de mens zag een venster ZONDER de code (of leeg) en OK leverde
#     alsnog af. Deze tests bewijzen dat het venster nu HELEMAAL NIET meer
#     getoond wordt voor zulke invoer.
# ---------------------------------------------------------------------------


def test_embedded_nul_in_aanduiding_is_rejected_before_any_window_is_shown():
    module = _load_module()
    calls = []
    exit_code, out, err = _run(
        module,
        _request_line(aanduiding="\x00voorstel A"),
        show_window=lambda text: calls.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert calls == []
    assert out == ""
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_embedded_nul_in_code_is_rejected_before_any_window_is_shown():
    module = _load_module()
    calls = []
    exit_code, out, err = _run(
        module,
        _request_line(code="\x00" + PLANTED_CODE),
        show_window=lambda text: calls.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert calls == []
    assert out == ""
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_embedded_nul_in_autoriteit_is_rejected_before_any_window_is_shown():
    module = _load_module()
    calls = []
    exit_code, out, err = _run(
        module,
        _request_line(autoriteit="https://voorbeeld.invalid/\x00goedkeuren"),
        show_window=lambda text: calls.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert calls == []
    assert out == ""
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_aanduiding_with_an_embedded_newline_forging_a_confirmation_line_is_rejected():
    """Een regeleinde in `aanduiding` is ook niet printbaar
    (`str.isprintable()` verwerpt `\\n`) - dezelfde regel die een vervalste
    tweede `bevestigingscode:`-regel tegenhoudt, precies zoals
    `confirm.marker_line()` dat al voor de PRODUCT-eigen marker doet."""
    module = _load_module()
    calls = []
    kwade_aanduiding = "voorstel A\nbevestigingscode: NEPCODE"
    exit_code, out, err = _run(
        module,
        _request_line(aanduiding=kwade_aanduiding),
        show_window=lambda text: calls.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert calls == []
    assert out == ""
    assert PLANTED_CODE not in out
    assert PLANTED_CODE not in err


def test_an_oversized_autoriteit_is_rejected_before_any_window_is_shown():
    """De redelijke lengtecap op de printbare velden (`_MAX_REQUEST_FIELD_LEN`)
    - een absurd grote waarde wordt geweigerd voordat er iets getoond wordt,
    in plaats van pas afgekapt bij weergave."""
    module = _load_module()
    calls = []
    exit_code, out, _err = _run(
        module,
        _request_line(autoriteit="https://voorbeeld.invalid/" + ("a" * 5000)),
        show_window=lambda text: calls.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert calls == []
    assert out == ""


# ---------------------------------------------------------------------------
# 11. De afleverregel wordt in EEN
#     write() + flush() geschreven, binnen dezelfde try - faalt een van
#     beide, dan volgt nooit exit 0.
# ---------------------------------------------------------------------------


class _WriteFailingStream:
    """`write()` faalt meteen - niets van de regel bereikt de stream."""

    def write(self, _data):
        raise OSError("kunstmatige schrijffout")

    def flush(self):
        pass


class _FlushFailingStream:
    """`write()` slaagt, `flush()` faalt - precies het geval waarbij dit kan
    optreden: de regel staat mogelijk in de stream, maar exit mag nooit 0
    zijn, want een ontvanger die het protocol volgt (SsoCodeChannel) leest
    stdout alleen bij returncode 0."""

    def __init__(self):
        self.written = []

    def write(self, data):
        self.written.append(data)
        return len(data)

    def flush(self):
        raise OSError("kunstmatige flushfout")


def test_a_failing_write_of_the_delivery_line_never_exits_0():
    module = _load_module()
    err = io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=_WriteFailingStream(),
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert exit_code != 0
    assert PLANTED_CODE not in err.getvalue()


def test_a_failing_flush_of_the_delivery_line_never_exits_0():
    module = _load_module()
    out = _FlushFailingStream()
    err = io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=out,
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    # Docstringclaim: de regel kan ondanks de mislukte flush al (deels) in
    # de stream staan (de write() zelf slaagde hier) - dat is geen lek,
    # want de exitcode is het enige wat een ontvanger mag vertrouwen.
    assert out.written
    assert exit_code != 0
    assert PLANTED_CODE not in err.getvalue()


class _SecondWriteFailingStream:
    """Faalt specifiek op de TWEEDE `write()`-aanroep - precies het geval
    dat tegen de OUDE code werd gemeten (de json-body-write
    slaagt, de aparte newline-write faalt daarna): op de oude code liet dat
    een VOLLEDIGE `afgeleverd: true`-JSON-body in de stream staan, ondanks
    exit 1. De huidige code bouwt de regel als EEN string en schrijft hem in
    EEN write()-aanroep - zo'n stream ziet dan nooit een tweede aanroep."""

    def __init__(self):
        self.calls = []

    def write(self, data):
        self.calls.append(data)
        if len(self.calls) == 2:
            raise OSError("kunstmatige fout op de tweede write-aanroep")
        return len(data)

    def flush(self):
        pass


def test_the_delivery_line_is_written_with_exactly_one_write_call():
    """Bewijst het structurele deel van I-B: geen aparte write() voor de
    json-body en dan nog een voor de newline meer - EEN write() met de
    volledige regel. Op de oude code ziet deze stream WEL een
    tweede aanroep en faalt die, wat toen exit 1 gaf terwijl de eerste
    write al de volledige `afgeleverd: true`-body had geschreven."""
    module = _load_module()
    out = _SecondWriteFailingStream()
    err = io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=out,
        stderr=err,
        show_window=lambda text: module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 0
    assert len(out.calls) == 1
    antwoord = json.loads(out.calls[0])
    assert antwoord["afgeleverd"] is True


# ---------------------------------------------------------------------------
# 12. KeyboardInterrupt faalt closed met
#     de ENE vaste reden, nooit een traceback.
# ---------------------------------------------------------------------------


def test_keyboard_interrupt_fails_closed_with_the_fixed_reason_not_a_traceback():
    module = _load_module()

    def boom(text):
        raise KeyboardInterrupt

    out, err = io.StringIO(), io.StringIO()
    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=out,
        stderr=err,
        show_window=boom,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert err.getvalue() == module._UNEXPECTED_FAILURE_REASON + "\n"
    assert "Traceback" not in err.getvalue()
    assert PLANTED_CODE not in err.getvalue()


# ---------------------------------------------------------------------------
# 13. Een kapotte err_stream in de
#     except-tak van main() zelf mag niet ontsnappen.
# ---------------------------------------------------------------------------


class _AlwaysRaisingStream:
    """Een stderr-vervanger waarvan `write()` altijd faalt - bewijst dat
    main()'s EIGEN poging om de vaste reden te melden niet zelf onbeheerd
    kan ontsnappen."""

    def write(self, _data):
        raise OSError("kunstmatige stderr-fout")

    def flush(self):
        pass


def test_a_broken_err_stream_does_not_escape_main_and_still_exits_1():
    module = _load_module()

    def boom(text):
        raise RuntimeError("onverwacht")

    exit_code = module.main(
        stdin=io.StringIO(_request_line()),
        stdout=io.StringIO(),
        stderr=_AlwaysRaisingStream(),
        show_window=boom,
        get_identity=lambda: IDENTITY,
    )
    assert exit_code == 1


# ---------------------------------------------------------------------------
# 14. Elke opzetfout in _show_window
#     (niet alleen de aanroep zelf) valt terug op dezelfde OSError die
#     _run() al als "het venster kon niet getoond worden" behandelt.
# ---------------------------------------------------------------------------


@_WINDOWS_ONLY
def test_show_window_wraps_any_winapi_setup_failure_as_oserror(monkeypatch):
    module = _load_module()
    fake_user32 = types.SimpleNamespace()  # geen MessageBoxW-attribuut
    fake_windll = types.SimpleNamespace(user32=fake_user32)
    monkeypatch.setattr(module.ctypes, "windll", fake_windll)

    with pytest.raises(OSError):
        module._show_window("tekst")


# ---------------------------------------------------------------------------
# 15. Een fout bij het lezen van
#     buffer.value valt nu binnen dezelfde try - deze indeling faalt
#     closed als "dit format loste niet op", niet als een ontsnapte
#     exceptie.
# ---------------------------------------------------------------------------


class _BrokenBuffer:
    """Een `create_unicode_buffer()`-vervanger waarvan `.value` faalt."""

    @property
    def value(self):
        raise ValueError("kunstmatige lees-fout")


@_WINDOWS_ONLY
def test_query_user_name_ex_treats_a_broken_buffer_read_as_this_format_failed(monkeypatch):
    module = _load_module()

    def handler(_name_format, buffer, grootte_ptr):
        if buffer is None:
            grootte_ptr.contents.value = 5
            return 0
        return 1

    fake_fn = _FakeWinapiFunc(handler)
    fake_secur32 = types.SimpleNamespace(GetUserNameExW=fake_fn)
    fake_windll = types.SimpleNamespace(secur32=fake_secur32)
    monkeypatch.setattr(module.ctypes, "windll", fake_windll)
    monkeypatch.setattr(module.ctypes, "create_unicode_buffer", lambda size: _BrokenBuffer())

    naam = module._query_user_name_ex(module.NAME_SAM_COMPATIBLE)

    assert naam is None


# ---------------------------------------------------------------------------
# 16. De isprintable()-eis zelf gekoppeld
#     aan code_channel._clean_answer_field, niet alleen de lengte.
# ---------------------------------------------------------------------------


def test_bevestiger_isprintable_requirement_matches_code_channel_clean_answer_field():
    """De lengtecap was al gepind; de isprintable()-regel
    zelf was met de hand gedupliceerd en nergens aan `_clean_answer_field`
    gekoppeld. Dit stuurt representatieve waarden door BEIDE kanten en
    eist dat ze het eens zijn over accepteren/afwijzen."""
    module = _load_module()
    gevallen = [
        "gewone tekst",
        "GJKDEMO\\operator",
        "naam met een\nregeleinde",
        "naam met een\ttab",
        "naam met een\x00nul",
        "geaccentueerd: caf\u00e9 \u00e0 la carte",
    ]
    for waarde in gevallen:
        schoon_ok = waarde.isprintable() and len(waarde) <= module._MAX_BEVESTIGER_LEN
        try:
            code_channel._clean_answer_field(waarde, "bevestiger")
            ontvanger_ok = True
        except code_channel.CodeChannelError:
            ontvanger_ok = False
        assert schoon_ok == ontvanger_ok, waarde


# ---------------------------------------------------------------------------
# 17. De weergavecap (_cap_for_display) was ongetest.
# ---------------------------------------------------------------------------


def test_display_cap_keeps_the_code_visible_for_an_oversized_aanduiding_and_autoriteit():
    """Waarden hier zitten BOVEN `_MAX_DISPLAY_FIELD_LEN` (200) maar ruim
    ONDER de leestijd-cap `_MAX_REQUEST_FIELD_LEN` (4096), zodat het
    verzoek geaccepteerd wordt en alleen de weergavecap gemeten wordt."""
    module = _load_module()
    lange_aanduiding = "voorstel A " + ("x" * 1000)
    lange_autoriteit = "https://voorbeeld.invalid/" + ("y" * 1000)
    seen = {}

    def capture(text):
        seen["text"] = text
        return module.IDOK

    _run(
        module,
        _request_line(aanduiding=lange_aanduiding, autoriteit=lange_autoriteit),
        show_window=capture,
        get_identity=lambda: IDENTITY,
    )
    tekst = seen["text"]
    assert PLANTED_CODE in tekst
    assert lange_aanduiding not in tekst
    assert lange_autoriteit not in tekst
    assert "..." in tekst
