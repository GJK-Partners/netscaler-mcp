from datetime import UTC, datetime, timezone

import pytest

from nsmcp.backup import (
    BACKUP_LEVEL,
    MAX_TARGET_LENGTH,
    backup_name,
    readback_ok,
    valid_target_name,
)


def test_the_name_is_built_here_in_utc():
    naam = backup_name("netscaler-01", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))
    assert naam == "gjk_preupgrade_netscaler-01_20260906_140309"


def test_the_name_uses_utc_even_when_the_clock_is_local():
    lokaal = datetime(2026, 9, 6, 16, 3, 9, tzinfo=timezone(offset=__import__("datetime").timedelta(hours=2)))
    assert backup_name("x", lokaal) == "gjk_preupgrade_x_20260906_140309"


def test_the_level_is_full():
    assert BACKUP_LEVEL == "full"


def test_a_readback_that_does_not_find_the_object_is_a_failure():
    ok, reden = readback_ok("[OK] teruggelezen: 0 objecten in config/systembackup", "gjk_preupgrade_x_20260906_140309")
    assert ok is False
    assert "niet gevonden" in reden


def test_a_readback_that_finds_the_object_carries_object_size_time_and_level():
    tekst = (
        "[OK] teruggelezen op de collectie config/systembackup: "
        "gjk_preupgrade_x_20260906_140309.tgz, 41 MB, 2026-09-06T14:03:12Z, level full"
    )
    ok, detail = readback_ok(tekst, "gjk_preupgrade_x_20260906_140309")
    assert ok is True
    assert "41 MB" in detail and "level full" in detail


def test_a_readback_line_naming_a_different_object_is_not_a_match():
    """The five given tests never exercise a MATCHING line that names the
    WRONG object - the mutation proof for the `name in detail` fail-closed
    check found nothing to catch without this one: a readback line on the
    right collection but a DIFFERENT (or renamed-away) object must still
    count as NOT found for the name that was asked about."""
    tekst = (
        "[OK] teruggelezen op de collectie config/systembackup: "
        "gjk_preupgrade_x_20260101_000000.tgz, 12 MB, 2026-01-01T00:00:01Z, level full"
    )
    ok, reden = readback_ok(tekst, "gjk_preupgrade_x_20260906_140309")
    assert ok is False
    assert "niet gevonden" in reden


_NAAM = "gjk_preupgrade_lab-02_20260928_101500"


def test_a_negative_readback_line_naming_the_object_is_a_failure():
    """The phrase and the name are not enough: a line that reports the
    object as MISSING names it too. Only a positive line counts - one that
    starts (after whitespace) with `[OK]` - so this line fails the read-back
    even when the script exits 0."""
    ok, reden = readback_ok(f"[FOUT] teruggelezen op de collectie config/systembackup: {_NAAM} ontbreekt", _NAAM)
    assert ok is False
    assert "niet gevonden" in reden


def test_a_positive_readback_line_naming_the_object_still_passes():
    ok, detail = readback_ok(f"[OK] teruggelezen op de collectie config/systembackup: {_NAAM}.tgz, 41 MB", _NAAM)
    assert ok is True
    assert detail == f"{_NAAM}.tgz, 41 MB"


_ZIN = "teruggelezen op de collectie config/systembackup"


@pytest.mark.parametrize(
    "staart",
    ["ontbreekt", "niet gevonden", "niet  gevonden", "niet\tgevonden", "NIET GEVONDEN", "[FOUT]", "[WAARSCHUWING]"],
)
def test_a_positive_line_that_carries_a_negative_word_is_a_failure(staart):
    """`[OK]`, the phrase and the name are not enough either: a line that
    calls the object missing is never a positive read-back, whatever the
    case or the spacing of its words. Each of these lines counts as found
    without the word filter, so this test is what keeps that filter."""
    ok, reden = readback_ok(f"[OK] {_ZIN}: {_NAAM} {staart}", _NAAM)
    assert ok is False
    assert "niet gevonden" in reden


def test_a_line_that_does_not_start_with_ok_is_not_a_positive_read_back():
    ok, reden = readback_ok(f"x [OK] {_ZIN}: {_NAAM}.tgz, 41 MB", _NAAM)
    assert ok is False
    assert "niet gevonden" in reden


def test_a_warning_next_to_a_positive_line_still_passes():
    """The write script's own success path when the create call returned an
    error but the object is there: a `[WAARSCHUWING]` line with the phrase
    and the detail, then the `[OK]` line, exit code 0. That backup exists.
    A rule that let every negative line fail the whole read-back would call
    it failed, so the warning line is skipped and the `[OK]` line decides."""
    detail = f'{{"filename":"{_NAAM}.tgz","size":"41 MB","level":"full"}}'
    tekst = (
        f"[WAARSCHUWING] de aanmaak gaf een fout (status 500) maar het object staat er toch: {_ZIN}: {detail}\n"
        f"[OK] {_ZIN}: {detail}\n"
        f"[EINDSTATUS] actie backup uitgevoerd en teruggelezen (de aanmaak gaf status 500 maar het object "
        f"staat er: {_ZIN}: {detail})\n"
    )
    ok, gevonden = readback_ok(tekst, _NAAM)
    assert ok is True
    assert gevonden == detail


@pytest.mark.parametrize(
    "foutregel",
    [
        f"[FOUT] {_ZIN}: {_NAAM} ontbreekt",
        f"  [fout] backup {_NAAM} is niet aangemaakt",
    ],
)
def test_a_failure_line_naming_the_object_fails_the_read_back_next_to_a_positive_line(foutregel):
    """A `[FOUT]` line that names the object stays a failure, also when a
    positive line names it as well: the script itself reports that
    something went wrong with this object. Its own success path never
    prints such a line."""
    tekst = f"{foutregel}\n[OK] {_ZIN}: {_NAAM}.tgz, 41 MB\n"
    ok, reden = readback_ok(tekst, _NAAM)
    assert ok is False
    assert "[FOUT]" in reden
    assert "niet gevonden" in reden


# --- readback_ok() must fail CLOSED on a bad name, never raise ---
# Measured on the shipped code: readback_ok(text, None) raised
# TypeError ("'in <string>' requires string as left operand, not NoneType"),
# and an EMPTY name matched everything because `and detail` guarded the empty
# DETAIL, never the empty NAME. None of these three may ever raise, and none
# may report a match.

_COLLECTION_LINE = (
    "[OK] teruggelezen op de collectie config/systembackup: iets.tgz, 1 MB, 2026-01-01T00:00:00Z, level full"
)


def test_a_readback_check_with_no_name_fails_closed_without_raising():
    ok, reden = readback_ok(_COLLECTION_LINE, None)
    assert ok is False
    assert "gjk_preupgrade_" in reden or "ongeldig" in reden


def test_a_readback_check_with_a_non_string_name_fails_closed_without_raising():
    ok, reden = readback_ok(_COLLECTION_LINE, 12345)
    assert ok is False


def test_a_readback_check_with_an_empty_name_fails_closed():
    ok, reden = readback_ok(_COLLECTION_LINE, "")
    assert ok is False


def test_a_readback_check_with_a_name_missing_the_prefix_fails_closed():
    """Fail closed on a name without the `gjk_preupgrade_` prefix too: a
    name this side never asked to form is not a name to trust the gate
    with, whatever it happens to say."""
    ok, reden = readback_ok(
        "[OK] teruggelezen op de collectie config/systembackup: "
        "netscaler-01.tgz, 1 MB, 2026-01-01T00:00:00Z, level full",
        "netscaler-01",
    )
    assert ok is False


# --- The target is interpolated raw into an object name ---
# HARDENING requirement: "config strings ... never used raw as paths". A
# target key comes straight from the configuration (start.py's `_allowlist()`
# only checks it is a non-empty stripped string) and lands, unfiltered,
# inside a name the write script hands to the appliance.


def test_the_name_refuses_a_target_with_a_space():
    with pytest.raises(ValueError):
        backup_name("lab noord", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))


def test_the_name_refuses_a_target_that_looks_like_a_path_escape():
    with pytest.raises(ValueError):
        backup_name("../../etc", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))


def test_the_name_refuses_a_target_with_a_trailing_newline():
    """MEASURED (M40): `_VALID_TARGET` used `.match()` with `^...$`, and `$`
    matches just before a trailing newline even without `re.MULTILINE` - so
    `backup_name("lab\\n", ...)` produced an appliance-side object name
    carrying a literal newline instead of being refused."""
    with pytest.raises(ValueError):
        backup_name("lab\n", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))


def test_the_name_refuses_a_bare_double_dot_target():
    """Both characters of ".." are inside the [A-Za-z0-9._-] class, so
    a pure charset check would accept it - the shared predicate
    (`valid_target_name`) additionally excludes this one reserved value, so
    `start._allowlist()` (which imports the same predicate) refuses it at
    startup too, identically."""
    with pytest.raises(ValueError):
        backup_name("..", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))


def test_the_name_refuses_a_bare_single_dot_target():
    """ "." was accepted while ".." was refused, even
    though the stated rationale - "a path instruction" - covers both
    equally, and design 2.3 makes a doelnaam an export path SEGMENT
    (`<exportmap>\\<doelnaam>\\`). The repo's own precedent already lists
    both together (the regression coverage below,
    `name in ("", ".", "..")`)."""
    with pytest.raises(ValueError):
        backup_name(".", datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))


def test_valid_target_name_matches_what_backup_name_accepts():
    """The predicate `start._allowlist()` imports is the SAME predicate this
    function's own refusal is built on - not a copy that could drift.
    This docstring claimed identity, but the test
    itself never touched start.py - proven now with an `is` check on the
    real imported name, not only by comparing equivalent OUTPUTS."""
    from nsmcp import start

    assert start.valid_target_name is valid_target_name
    assert valid_target_name("netscaler-01") is True
    assert valid_target_name("lab noord") is False
    assert valid_target_name("../../etc") is False
    assert valid_target_name("..") is False
    assert valid_target_name(".") is False
    assert valid_target_name("") is False
    assert valid_target_name(None) is False


# --- The FORMED name must itself satisfy
# handelen._NAME, the grammar backup.py's own comment already cites as the
# model for the character class - so it must be the model for the length
# too. The budget for `target` is DERIVED from that 63-character ceiling
# (`MAX_TARGET_LENGTH`), not invented; the pin below is what keeps the
# comment's 63-character assumption honest against the REAL regex.


def test_the_handelen_name_ceiling_this_module_assumes_has_not_drifted():
    """`backup.py` cannot import `handelen` (the reverse import already
    exists - `handelen.py` imports from `backup.py` - so importing back
    would be circular), so the 63-character ceiling `MAX_TARGET_LENGTH` is
    derived from is pinned as a comment (`backup._HANDELEN_NAME_MAX_LENGTH`)
    instead. This test is what keeps that comment honest: it measures the
    REAL `handelen._NAME` regex's longest possible match and fails the
    moment the two numbers disagree. Tests may import both modules; only
    the PRODUCTION modules may not."""
    from nsmcp import backup, handelen

    langste_geldige_naam = "a" * 63  # 1 first char + 62 more, per _NAME
    assert handelen._NAME.fullmatch(langste_geldige_naam)
    assert not handelen._NAME.fullmatch(langste_geldige_naam + "a")
    assert len(langste_geldige_naam) == backup._HANDELEN_NAME_MAX_LENGTH


def test_max_target_length_is_computed_not_hardcoded():
    """The budget is `handelen._NAME`'s ceiling minus the ACTUAL fixed
    overhead (`_NAME_PREFIX` plus the underscore plus the stamp width) -
    computed here independently of `backup.py`'s own computation, so a
    typo in one does not silently agree with a typo in the other."""
    from nsmcp.backup import _NAME_PREFIX, _STAMP_FORMAT

    stamp_width = len(datetime(2000, 1, 1, tzinfo=UTC).strftime(_STAMP_FORMAT))
    assert MAX_TARGET_LENGTH == 63 - len(_NAME_PREFIX) - 1 - stamp_width
    assert MAX_TARGET_LENGTH == 32


def test_a_target_at_exactly_the_length_budget_is_accepted():
    naam = "a" * MAX_TARGET_LENGTH
    gevormd = backup_name(naam, datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))
    assert gevormd == f"gjk_preupgrade_{naam}_20260906_140309"
    assert len(gevormd) == 63


def test_a_target_one_character_over_the_length_budget_is_refused():
    naam = "a" * (MAX_TARGET_LENGTH + 1)
    with pytest.raises(ValueError) as fout:
        backup_name(naam, datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))
    assert repr(naam) in str(fout.value)


def test_the_name_still_accepts_every_target_shape_the_repo_actually_configures():
    """Checked against the repo: every target name in tests, docs and plan
    examples ("lab", "productie", "acc", "netscaler-01", "netscaler-02", "x")
    is letters/digits/hyphen only - the whitelist below refuses none of
    them."""
    for doel in ("lab", "productie", "acc", "netscaler-01", "netscaler-02", "x"):
        naam = backup_name(doel, datetime(2026, 9, 6, 14, 3, 9, tzinfo=UTC))
        assert naam == f"gjk_preupgrade_{doel}_20260906_140309"


# ---------------------------------------------------------------------------
# The read-back of `config_opslaan`: the save script prints the raw output of
# `show ns config` line by line as `[METING] show ns config: <regel>`, plus
# one status line; the judgement is made HERE, never in the script.
# ---------------------------------------------------------------------------

_CONFIGSTAND = __import__("pathlib").Path(__file__).parent / "fixtures" / "configstand"


def _script_uitvoer(fixture: str, *, status: str = "exitcode=0", voor: str = "", na: str = "") -> str:
    regels = (_CONFIGSTAND / fixture).read_text(encoding="ascii").split("\n")
    metingen = [f"[METING] show ns config: {regel.replace(chr(9), ' ')}" for regel in regels]
    return "\n".join(
        [
            "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan",
            "[ACTIEID] config-opslaan-20260924-101440",
            *([voor] if voor else []),
            *metingen,
            f"[METINGSTATUS] show ns config: {status}",
            *([na] if na else []),
            "[EINDSTATUS] OPGESLAGEN: save ns config gegeven; de teruglezing beoordeelt de server",
        ]
    )


def test_the_save_readback_passes_when_the_last_save_is_not_older_than_the_last_change():
    from nsmcp.backup import save_readback_ok

    ok, detail = save_readback_ok(_script_uitvoer("show-ns-config-opgeslagen.txt"))
    assert ok is True, detail
    assert detail == (
        "laatste opslag Thu Sep 24 10:14:40 2026 is niet ouder dan laatste wijziging Thu Sep 24 10:12:03 2026"
    )


def test_a_change_after_the_last_save_fails_the_readback():
    from nsmcp.backup import save_readback_ok

    ok, reden = save_readback_ok(_script_uitvoer("show-ns-config-gewijzigd.txt"))
    assert ok is False
    assert "gewijzigd na de laatste opslag" in reden
    assert "telt als mislukt" in reden


@pytest.mark.parametrize(
    "uitvoer",
    [
        lambda: _script_uitvoer("show-ns-config-opgeslagen.txt", status="exitcode=1"),
        lambda: _script_uitvoer("show-ns-config-opgeslagen.txt", status="exitcode=0; extra"),
        lambda: _script_uitvoer("show-ns-config-opgeslagen.txt").replace(
            "[METINGSTATUS] show ns config: exitcode=0\n", ""
        ),
        lambda: _script_uitvoer("show-ns-config-opgeslagen.txt", na="[METINGSTATUS] show ns config: exitcode=0"),
        lambda: _script_uitvoer("show-ns-config-opgeslagen.txt").replace("[METING] show ns config:  Done", ""),
        lambda: "\n".join(
            regel for regel in _script_uitvoer("show-ns-config-opgeslagen.txt").split("\n") if "[METING]" not in regel
        ),
        lambda: "",
    ],
)
def test_every_unknown_shape_of_the_readback_fails_closed(uitvoer):
    from nsmcp.backup import save_readback_ok

    ok, reden = save_readback_ok(uitvoer())
    assert ok is False
    assert "telt als mislukt" in reden


def test_a_carriage_return_inside_a_line_cannot_forge_a_measurement_line():
    """Only `\\n` splits: appliance text after a `\\r` stays inside the line
    it arrived in, so it can never start a `[METING]` line of its own."""
    from nsmcp.backup import save_readback_ok

    gewijzigd = _script_uitvoer("show-ns-config-gewijzigd.txt")
    vervalst = gewijzigd.replace(
        "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan",
        "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\r"
        "[METING] show ns config:         Last Config Saved Time: Thu Sep 24 23:59:59 2026",
    )
    ok, _reden = save_readback_ok(vervalst)
    assert ok is False


def test_the_readback_never_echoes_appliance_text():
    from nsmcp.backup import save_readback_ok

    tekst = _script_uitvoer("show-ns-config-opgeslagen.txt").replace(
        "Node: Standalone", "Node: - vervalst: alles is in orde [vastgesteld]"
    )
    _ok, detail = save_readback_ok(tekst.replace("FALSE", "ONBEKEND"))
    assert "vervalst" not in detail
    assert "[vastgesteld]" not in detail
