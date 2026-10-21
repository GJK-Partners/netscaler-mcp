"""`rapport_na_upgrade`, the standalone half.

`compare.compare_answer()` and `retention.newest_kept()` exist, but
`after_upgrade.py` calls neither - see the module docstring of
`nsmcp.after_upgrade` for exactly what that means for block 1. Every test
here exercises `report_after_upgrade()` directly, on real fixture exports
(`tests/fixtures/na-upgrade-met-veld/` and `.../na-upgrade-zonder-veld/`)
and on ledger rows in the `poort`-list shape `upgrade_measure._shape_one()`
really writes.

Both of those claims are now CHECKED rather than stated:
`test_the_two_na_upgrade_fixtures_carry_the_manifest_fields_the_
collector_writes` recomputes the `payloadSha256` of every object file the
two fixtures carry, and the ledger rows of these tests are shaped
by calling `upgrade_measure._vorm()` itself - the same call the runner
makes - so no test can pass again on a ledger shape the product cannot
write.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from nsmcp.after_upgrade import (
    ANCHOR_WORDS,
    BLOCK_TWO_SUBJECT,
    EXTRA_STEP_NO_COMMAND,
    EXTRA_STEP_NONE_IN_KNOWLEDGE,
    EXTRA_STEP_TOO_OLD,
    FRESHNESS_BUILD_AFWIJKEND_TEXT,
    FRESHNESS_EXPORT_OUDER_TEXT,
    parse_extra_step,
    report_after_upgrade,
)
from nsmcp.cve import GERAAKT, NIET_GERAAKT, NIET_VASTGESTELD
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.upgrade import FAMILIES

FIXTURES = Path(__file__).parent / "fixtures"

# The sentence used as a header - CVE-2026-13474 is a
# fixture identifier only, not a real bulletin.
EXTRA_STEP_SENTENCE = (
    "Voor CVE-2026-13474: op appliances zonder HTTP Strict Profiles na de upgrade "
    "`set ns httpProfile <profiel> -http2SmallWndTimeout 30` zetten (vendor)."
)

BULLETIN = {
    "bulletin": "CTX-DEMO-13474",
    "datum": "2026-08-19",
    "getroffen": {"14.1": "< 72.61"},
    "fix": {"14.1": "72.61"},
    "cves": [
        {
            "id": "CVE-2026-13474",
            "cvss": 7.5,
            "kern": "HTTP/2 window handling",
            "voorwaarde": "altijd",
        }
    ],
    "advies": "Upgrade naar 14.1-72.61 of hoger.",
    "extraStapNaUpgrade": EXTRA_STEP_SENTENCE,
}

BULLETIN_ZONDER_STAP = {
    "bulletin": "CTX-DEMO-00000",
    "datum": "2026-08-19",
    "getroffen": {"14.1": "< 72.61"},
    "fix": {"14.1": "72.61"},
    "cves": [
        {"id": "CVE-2026-00000", "cvss": 5.0, "kern": "iets anders", "voorwaarde": "altijd"},
    ],
    "advies": "Upgrade naar 14.1-72.61 of hoger.",
    "extraStapNaUpgrade": "",
}


def _knowledge(*bulletins, **kwargs) -> Knowledge:
    return Knowledge(
        version="2026.09",
        date="2026-09-06",
        age_days=0,
        missing=False,
        cve=tuple(bulletins),
        **kwargs,
    )


@pytest.fixture
def knowledge() -> Knowledge:
    return _knowledge(BULLETIN)


@pytest.fixture
def export_met_veld():
    return load_export(FIXTURES / "na-upgrade-met-veld")


@pytest.fixture
def export_zonder_veld():
    return load_export(FIXTURES / "na-upgrade-zonder-veld")


# ---------------------------------------------------------------------------
# Ledger fixtures: R0's `voormeting_vast` row and R5's closing row, in the
# same `poort`-list shape `upgrade_measure._shape_one()`/`anchor_evidence_
# gate()`/`family_counts_gate()` really write (`upgrade.py`), not a
# reinvented shortcut.
# ---------------------------------------------------------------------------

ANKER_A = hashlib.sha256(b"r0-r5-same-config-anchor").hexdigest()
ANKER_B = hashlib.sha256(b"r0-r5-different-config-anchor-on-r5").hexdigest()

FAMILIETELLINGEN_BEWIJS = (
    "familietellingen: lbvserver=2, csvserver=1, vpnvserver=0, "
    "authenticationvserver=0, service=2, servicegroup=1, sslcertkey=1, lbmonitor=1"
)


def _anker_poort(anker: str, *, encryptionparams=2, rpcnode=1, encrypted=1) -> dict:
    volgorde = f"-encrypted={encrypted}, set ns encryptionParams={encryptionparams}, set ns rpcNode={rpcnode}"
    return {
        "naam": "configuratie-anker",
        "type": "bewijs",
        "uitkomst": "open",
        "bewijs": f"anker={anker}; {volgorde}",
        "reden": "",
    }


def _familie_poort() -> dict:
    return {
        "naam": "familietellingen",
        "type": "bewijs",
        "uitkomst": "open",
        "bewijs": FAMILIETELLINGEN_BEWIJS,
        "reden": "",
    }


def _rij(*, fase: str, gebeurtenis: str, poort: list, run: str = "r1", doel: str = "lab-01", tijd: str) -> dict:
    return {
        "tijd": tijd,
        "run": run,
        "doel": doel,
        "fase": fase,
        "gebeurtenis": gebeurtenis,
        "poort": poort,
        "uitkomst": "geslaagd",
        "bewijs": "test-fixture",
        "actieid": "a-1",
        "bevestiger": "tester",
        "gestart": tijd,
        "geeindigd": tijd,
    }


def _r0(poort, *, tijd: str = "2026-09-06T08:00:00Z") -> dict:
    return _rij(fase="R0", gebeurtenis="voormeting_vast", poort=poort, tijd=tijd)


def _r5(poort, *, tijd: str = "2026-09-06T12:00:00Z") -> dict:
    return _rij(fase="R5", gebeurtenis="fase_geslaagd", poort=poort, tijd=tijd)


@pytest.fixture
def ledger_met_anker() -> tuple:
    poort = [_anker_poort(ANKER_A), _familie_poort()]
    return (_r0(poort), _r5(poort))


@pytest.fixture
def ledger_ander_anker() -> tuple:
    return (_r0([_anker_poort(ANKER_A), _familie_poort()]), _r5([_anker_poort(ANKER_B), _familie_poort()]))


@pytest.fixture
def ledger_ander_blobtal() -> tuple:
    return (
        _r0([_anker_poort(ANKER_A, encryptionparams=2), _familie_poort()]),
        _r5([_anker_poort(ANKER_A, encryptionparams=3), _familie_poort()]),
    )


# ---------------------------------------------------------------------------
# The anchor words and the extra-step vocabulary, verbatim.
# ---------------------------------------------------------------------------


def test_the_three_anchor_words_are_exactly_these_three():
    assert ANCHOR_WORDS == ("gelijk", "verschillend", "niet vastgesteld")


def test_the_extra_step_is_its_own_check_with_the_cve_vocabulary(export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=()).to_text()
    assert "extra stap na de upgrade" in tekst
    assert any(woord in tekst for woord in ("GERAAKT", "NIET GERAAKT", "NIET VASTGESTELD"))


def test_a_missing_field_says_the_build_is_too_old_and_never_geraakt(export_zonder_veld, knowledge):
    tekst = report_after_upgrade(export_zonder_veld, export_zonder_veld, knowledge, ledger_lines=()).to_text()
    assert EXTRA_STEP_TOO_OLD == "build te oud, stap nog niet mogelijk"
    assert EXTRA_STEP_TOO_OLD in tekst
    assert "NIET VASTGESTELD" in tekst
    regel = [r for r in tekst.splitlines() if EXTRA_STEP_TOO_OLD in r][0]
    assert "GERAAKT" not in regel.replace("NIET VASTGESTELD", "")


def test_the_extra_step_reads_its_object_and_parameter_from_the_sentence():
    zin = (
        "Voor CVE-2026-13474: op appliances zonder HTTP Strict Profiles na de upgrade "
        "`set ns httpProfile <profiel> -http2SmallWndTimeout 30` zetten (vendor)."
    )
    assert parse_extra_step(zin) == ("config/nshttpprofile", "http2smallwndtimeout", "30")
    assert parse_extra_step("zet iets goed") is None
    assert parse_extra_step("") is None


def test_the_anchor_comes_from_the_ledger_of_r0_and_r5(ledger_met_anker, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_met_anker).to_text()
    assert "anker" in tekst
    assert "gelijk" in tekst


def test_a_different_anchor_is_reported_as_verschillend(ledger_ander_anker, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_ander_anker).to_text()
    assert "verschillend" in tekst


def test_a_missing_anchor_line_is_not_established_never_gelijk(export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=()).to_text()
    assert "niet vastgesteld" in tekst


def test_the_report_names_the_number_of_excluded_blob_lines_per_kind(ledger_met_anker, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_met_anker).to_text()
    for soort in ("set ns encryptionParams", "set ns rpcNode", "-encrypted"):
        assert soort in tekst


def test_a_changed_blob_count_is_reported_as_a_difference(ledger_ander_blobtal, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_ander_blobtal).to_text()
    assert "verschillend" in tekst


def test_the_eight_family_counts_come_from_r0_and_r5(ledger_met_anker, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_met_anker).to_text()
    for familie in FAMILIES:
        assert familie in tekst


# ---------------------------------------------------------------------------
# The other two branches of the extra-step table, the
# never-silent block 1 gap, hardening on the knowledge-derived tokens, and a
# defensive check on the never-echoed confirmation code.
# ---------------------------------------------------------------------------


def test_the_extra_step_says_niet_geraakt_when_the_value_matches(export_met_veld, knowledge):
    """`export_met_veld`'s own profile carries `http2smallwndtimeout=30`,
    exactly the value the bulletin's sentence asks for - the fixture's
    OTHER demonstrated branch (`export_zonder_veld` above proves NIET
    VASTGESTELD): the step has already run."""
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=()).to_text()
    regel = [r for r in tekst.splitlines() if "extra stap na de upgrade" in r][0]
    assert NIET_GERAAKT in regel
    assert "de extra stap is uitgevoerd" in tekst


def test_the_extra_step_says_geraakt_when_the_value_differs(export_met_veld, knowledge):
    afwijkend = _knowledge(
        {
            **BULLETIN,
            "extraStapNaUpgrade": (
                "Voor CVE-2026-13474: `set ns httpProfile <profiel> -http2SmallWndTimeout 60` zetten."
            ),
        }
    )
    tekst = report_after_upgrade(export_met_veld, export_met_veld, afwijkend, ledger_lines=()).to_text()
    regel = [r for r in tekst.splitlines() if "extra stap na de upgrade" in r][0]
    assert GERAAKT in regel
    assert "NIET " + GERAAKT not in regel
    assert "de extra stap moet nog" in tekst


def test_an_unparseable_sentence_is_niet_vastgesteld_with_its_own_reason(export_met_veld):
    onherkenbaar = _knowledge({**BULLETIN, "extraStapNaUpgrade": "zet iets goed na de upgrade"})
    tekst = report_after_upgrade(export_met_veld, export_met_veld, onherkenbaar, ledger_lines=()).to_text()
    assert EXTRA_STEP_NO_COMMAND == "de extra stap noemt geen herkenbaar commando"
    assert EXTRA_STEP_NO_COMMAND in tekst
    assert EXTRA_STEP_TOO_OLD not in tekst


def test_no_bulletin_with_an_extra_step_is_named_honestly_not_omitted(export_met_veld):
    """`BULLETIN_ZONDER_STAP` is a REAL CVE bulletin (block 2 legitimately
    calls it GERAAKT on this build) that simply carries no extra step - the
    two blocks are independent checks, so this only pins the EXTRA-STEP
    line, never the whole answer."""
    geen_stap = _knowledge(BULLETIN_ZONDER_STAP)
    tekst = report_after_upgrade(export_met_veld, export_met_veld, geen_stap, ledger_lines=()).to_text()
    regel = [r for r in tekst.splitlines() if EXTRA_STEP_NONE_IN_KNOWLEDGE in r][0]
    assert "extra stap na de upgrade" in regel
    assert "GERAAKT" not in regel


def test_block_one_is_named_as_not_assessed_never_silently_missing(export_met_veld, knowledge):
    """Block 1 is deliberately not wired up yet - see the
    module docstring. The gap must be a NAMED `NotAssessed`, never an
    absence a reader could mistake for 'nothing to report'."""
    antwoord = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=())
    onderwerpen = [n.subject for n in antwoord.not_assessed]
    assert any("bron" in s for s in onderwerpen)
    tekst = antwoord.to_text()
    assert "NIET BEOORDEELD IN DEZE VERSIE" in tekst


def test_the_extra_step_value_token_is_bounded_not_unbounded():
    """Every token is shape-constrained AND bounded on both sides, and a
    contiguous run past a bound REJECTS instead of being cut down to it
    (`NIET VASTGESTELD`, never a crash and never an unbounded echo).

    The VALUE used to be the exception here: it has no natural terminator
    besides whitespace/backtick/sentence end, so an over-long run was
    TRUNCATED to 80 characters. That
    truncated value is not an echo, it is the left-hand side of the
    GERAAKT / NIET GERAAKT comparison two functions down - an 81-character
    value that the export carries in full would be judged as "not the
    expected value" and reported as a step still outstanding. A value this
    parser cannot read whole is a value it has not read."""
    assert parse_extra_step("set ns httpProfile -flag " + ("x" * 5000)) is None
    kort = parse_extra_step("set ns httpProfile -flag " + ("x" * 80))
    assert kort == ("config/nshttpprofile", "flag", "x" * 80)


def test_the_confirmation_code_never_appears_in_the_answer(ledger_met_anker, export_met_veld, knowledge):
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_met_anker).to_text()
    assert "bevestigingscode" not in tekst.lower()


def test_a_hostile_count_in_the_ledger_never_crashes_the_report(export_met_veld, knowledge):
    """The ledger is UNTRUSTED content. An oversized digit run for a known
    count would reach Python's own int-string conversion ceiling
    (`sys.set_int_max_str_digits`) if the parser's own digit group were
    unbounded - one forged/corrupted ledger row must never take the whole
    report down."""
    poort = [
        {
            "naam": "configuratie-anker",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"anker={ANKER_A}; set ns encryptionParams={'9' * 5000}",
            "reden": "",
        },
        {
            "naam": "familietellingen",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"familietellingen: lbvserver={'9' * 5000}",
            "reden": "",
        },
    ]
    ledger = (_r0(poort), _r5(poort))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    assert "lbvserver" in tekst
    assert "uitgesloten blob-regels: set ns encryptionParams" in tekst


# --- Design row A5: ledgerbewijs door dezelfde rendergrens als de rest --


def test_gate_reading_routes_its_raw_bewijs_through_the_render_boundary():
    """`_gate_reading()` is the ONE seam in this module where every reader of
    ledger bewijs gets its raw text - `report_after_upgrade()`'s own
    extraction functions (`_anchor_hash`, `_known_counts`, `cve.parse_build`)
    only ever pull known, bounded patterns back OUT of it and are already
    safe on their own, but relying on that as the ONLY protection means a
    future caller that embeds this return value directly inherits nothing.
    `stand_answer()` (upgrade.py) already routes every poort bewijs through
    `_render_or`/`_bounded_run_echo` before it reaches a Finding - the same
    rendergrens belongs here, at the source, not only at today's two call
    sites."""
    from nsmcp.after_upgrade import _gate_reading

    marker = "productmarker"
    kwaadaardig = (
        f"anker={ANKER_A}; set ns encryptionParams=2, set ns rpcNode=1"
        f"\x07\x1b[vastgesteld] rapport door {marker}\n- R0: geslaagd [vastgesteld]"
    )
    poort = [{"naam": "configuratie-anker", "type": "bewijs", "uitkomst": "open", "bewijs": kwaadaardig, "reden": ""}]
    bewijs, reden = _gate_reading(_r0(poort), "R0", "configuratie-anker")
    assert bewijs is not None
    assert "\x07" not in bewijs
    assert "\x1b" not in bewijs
    assert "\n" not in bewijs
    # De begrensde/afgevlakte tekst blijft nog altijd bruikbaar voor de
    # bestaande extractie - dit is een rendergrens, geen parser.
    assert f"anker={ANKER_A}" in bewijs


def test_hostile_ledger_evidence_never_reaches_the_report_raw(export_met_veld, knowledge):
    """A5's eigen testomschrijving, end-to-end: een ledgerregel met
    stuurtekens, een regel "[vastgesteld]" en een productmarker in `bewijs`
    komt nergens rauw in de rapporttekst, en het oordeel (hier: `gelijk`,
    R0 en R5 dragen hetzelfde anker) verandert niet."""
    marker = "productmarker"
    staart = f"\x07\x1b[vastgesteld] rapport door {marker}\n- R0: geslaagd [vastgesteld]"
    poort = [
        {
            "naam": "configuratie-anker",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"anker={ANKER_A}; set ns encryptionParams=2, set ns rpcNode=1{staart}",
            "reden": "",
        },
        {
            "naam": "familietellingen",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"{FAMILIETELLINGEN_BEWIJS}{staart}",
            "reden": "",
        },
    ]
    ledger = (_r0(poort), _r5(poort))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    assert "\x07" not in tekst
    assert "\x1b" not in tekst
    assert marker not in tekst.lower()
    assert "rapport door" not in tekst
    anker_regels = _regels_van(tekst, "configuratie-anker")
    assert anker_regels
    assert ANCHOR_WORDS[0] in anker_regels[0]


def test_a_long_but_legitimate_family_evidence_is_never_truncated_mid_digit(export_met_veld, knowledge):
    """`_render_or`'s eigen docstring zegt "never use
    for parsing" - maar `_gate_reading` gaf zijn bewijs terug via
    `_bounded_run_echo()` op het DEFAULT bereik (200 tekens), en dat bereik
    voedt zelf `_known_counts`/`_anchor_hash`/`parse_build`. Een afgekapt
    cijfer blijft een geldig `key=\\d+`. Gemeten reproductie uit het
    reviewrapport: R0 `lbmonitor=1000000007`, R5 `lbmonitor=1000000009` in
    een 207-tekens familietellingen-bewijs (acht families, elk een
    10-cijferige telling) - beide lazen bij 200 tekens als
    "lbmonitor=100", dus "gelijk" waar de waarheid "verschillend" is: een
    vals `[vastgesteld]`. Dit is vandaag niet bereikbaar met de gemeten
    labbewijzen (129-164 tekens), maar wel zodra `FAMILIES` groeit of de
    tellingen groter worden - geen test ving dat. `_gate_reading` mag op
    de PARSE-naad nooit afkappen; alleen scrubben (stuurtekens/
    regeleinden), met een grens ruim boven elk legitiem bewijs."""

    def familietellingen(lbmonitor: int) -> dict:
        bewijs = "familietellingen: " + ", ".join(
            f"{fam}={v}"
            for fam, v in [
                ("lbvserver", 2000000001),
                ("csvserver", 1000000001),
                ("vpnvserver", 3000000001),
                ("authenticationvserver", 4000000001),
                ("service", 2000000001),
                ("servicegroup", 1000000001),
                ("sslcertkey", 1000000001),
                ("lbmonitor", lbmonitor),
            ]
        )
        assert len(bewijs) > 200, "de reproductie moet de oude 200-tekens-grens overschrijden"
        return {"naam": "familietellingen", "type": "bewijs", "uitkomst": "open", "bewijs": bewijs, "reden": ""}

    poort_r0 = [_anker_poort(ANKER_A), familietellingen(1000000007)]
    poort_r5 = [_anker_poort(ANKER_A), familietellingen(1000000009)]
    ledger = (_r0(poort_r0), _r5(poort_r5))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    lb = _regels_van(tekst, "familietelling: lbmonitor")
    assert lb
    assert ANCHOR_WORDS[1] in lb[0], lb[0]  # "verschillend" - nooit "gelijk"
    assert "1000000007" in tekst
    assert "1000000009" in tekst


def test_gate_reading_does_not_truncate_the_longest_legitimate_family_evidence():
    """Op functieniveau: het langst plausibele `familietellingen`-bewijs
    (acht families, elke telling op de eigen parsergrens van 15 cijfers -
    `_known_counts`' eigen `\\d{1,15}`) komt met elke telling intact uit
    `_gate_reading` - niet slechts "lang genoeg om vandaag te werken"."""
    from nsmcp.after_upgrade import _gate_reading

    langste = "familietellingen: " + ", ".join(
        f"{fam}={'9' * 15}"
        for fam in (
            "lbvserver",
            "csvserver",
            "vpnvserver",
            "authenticationvserver",
            "service",
            "servicegroup",
            "sslcertkey",
            "lbmonitor",
        )
    )
    poort = [{"naam": "familietellingen", "type": "bewijs", "uitkomst": "open", "bewijs": langste, "reden": ""}]
    bewijs, _reden = _gate_reading(_r0(poort), "R0", "familietellingen")
    assert bewijs == langste, (len(bewijs), len(langste))


# --- `_ANCHOR_HASH_RE` had no right boundary --------------------------


def test_an_oversized_anchor_digest_has_no_right_boundary_is_never_truncated():
    """Without `(?![0-9a-fA-F])`, `anker=<128 hex>` matched on the
    FIRST 64 of them - two genuinely different 128-character digests
    sharing only their first 64 characters then read as the SAME anchor,
    silently. An over-long digest is now no match at all."""
    from nsmcp.after_upgrade import _anchor_hash, _blob_segment

    gedeeld_prefix = hashlib.sha256(b"gedeeld-prefix").hexdigest()
    a_128 = gedeeld_prefix + hashlib.sha256(b"staart-a").hexdigest()
    b_128 = gedeeld_prefix + hashlib.sha256(b"staart-b").hexdigest()
    assert a_128[:64] == b_128[:64]
    assert a_128 != b_128

    bewijs_a = f"anker={a_128}; set ns encryptionParams=2, set ns rpcNode=1"
    bewijs_b = f"anker={b_128}; set ns encryptionParams=2, set ns rpcNode=1"
    assert _anchor_hash(bewijs_a) is None
    assert _anchor_hash(bewijs_b) is None
    assert _blob_segment(bewijs_a) is None
    # A well-formed, exactly-64-character digest is unaffected.
    assert _anchor_hash(f"anker={ANKER_A}; set ns encryptionParams=2") == ANKER_A


def test_an_oversized_anchor_digest_never_fabricates_a_false_gelijk(export_met_veld, knowledge):
    """The report-level version of the unit test above: two 128-character
    digests sharing a 64-character prefix used to render `gelijk: R0=0,
    R5=0 [vastgesteld]` on every blob kind, and `gelijk` on the anchor line
    itself - a comparison of a digest this parser never read in full. Both
    must now read `niet vastgesteld`."""
    gedeeld_prefix = hashlib.sha256(b"gedeeld-prefix-report").hexdigest()
    a_128 = gedeeld_prefix + hashlib.sha256(b"staart-a-report").hexdigest()
    b_128 = gedeeld_prefix + hashlib.sha256(b"staart-b-report").hexdigest()
    poort_r0 = [
        {
            "naam": "configuratie-anker",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"anker={a_128}; set ns encryptionParams=2, set ns rpcNode=1",
            "reden": "",
        },
        _familie_poort(),
    ]
    poort_r5 = [
        {
            "naam": "configuratie-anker",
            "type": "bewijs",
            "uitkomst": "open",
            "bewijs": f"anker={b_128}; set ns encryptionParams=2, set ns rpcNode=1",
            "reden": "",
        },
        _familie_poort(),
    ]
    ledger = (_r0(poort_r0), _r5(poort_r5))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    anker_regels = _regels_van(tekst, "configuratie-anker")
    assert anker_regels
    assert "gelijk" not in anker_regels[0]
    assert ANCHOR_WORDS[2] in anker_regels[0]
    blob_regels = _regels_van(tekst, "uitgesloten blob-regels: set ns encryptionParams")
    assert blob_regels
    assert "R0=0, R5=0" not in blob_regels[0]
    assert ANCHOR_WORDS[2] in blob_regels[0]


# --- Block 2 is judged only on an export PROVEN to postdate the upgrade -


def _doelbuild_bereikt_poort(bewijs: str = "show ns version: NetScaler NS14.1: Build 72.57.nc") -> dict:
    return {
        "naam": "doelbuild bereikt",
        "type": "bewijs",
        "uitkomst": "open",
        "bewijs": bewijs,
        "reden": "",
    }


def test_block_two_is_niet_vastgesteld_when_r5_never_closed(export_met_veld, knowledge):
    """No R5 closing row at all - there is no upgrade to date the export
    against, so block 2 cannot claim a verdict "op de nieuwe build"."""
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=()).to_text()
    regels = _regels_van(tekst, BLOCK_TWO_SUBJECT)
    assert regels
    assert NIET_VASTGESTELD in regels[0]
    assert "R0 en/of R5" not in regels[0]


def test_block_two_is_niet_vastgesteld_when_the_export_is_older_than_the_upgrade(
    export_met_veld,
    knowledge,
):
    """`export_met_veld` was collected at 09:00; R5's default row here
    closes at 12:00 - an OLDER export, presented as the new build, is
    exactly the false [vastgesteld] this finding exists to stop."""
    ledger = (_r0([_doelbuild_bereikt_poort()]), _r5([_doelbuild_bereikt_poort()]))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    regels = _regels_van(tekst, BLOCK_TWO_SUBJECT)
    assert regels
    assert NIET_VASTGESTELD in regels[0]
    assert FRESHNESS_EXPORT_OUDER_TEXT in "\n".join(regels)
    assert "GERAAKT" not in regels[0]


def test_block_two_is_niet_vastgesteld_when_the_export_build_does_not_match_r5(
    export_met_veld,
    knowledge,
):
    """The export postdates R5 this time (R5 closes BEFORE it was
    collected), but R5 read a DIFFERENT build live than the one this
    export itself carries (72.57 here vs. 72.61 in the fixture) - still
    not provable as the same post-upgrade state."""
    ledger = (
        _r0([_doelbuild_bereikt_poort()], tijd="2026-09-06T07:00:00Z"),
        _r5(
            [_doelbuild_bereikt_poort("show ns version: NetScaler NS14.1: Build 72.61.nc")], tijd="2026-09-06T08:00:00Z"
        ),
    )
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    regels = _regels_van(tekst, BLOCK_TWO_SUBJECT)
    assert regels
    assert NIET_VASTGESTELD in regels[0]
    assert FRESHNESS_BUILD_AFWIJKEND_TEXT in "\n".join(regels)


def test_block_two_still_gives_a_real_verdict_on_a_genuinely_fresh_export(
    export_met_veld,
    knowledge,
):
    """The happy path this fix must not break: an export collected AFTER
    R5 closed, on the SAME build R5 itself read live, still gets block
    2's real CVE verdict - `export_met_veld` carries 14.1-72.57, and
    `knowledge`'s BULLETIN affects "< 72.61", so this is a real GERAAKT,
    not a stand-in."""
    ledger = (
        _r0([_doelbuild_bereikt_poort()], tijd="2026-09-06T07:00:00Z"),
        _r5([_doelbuild_bereikt_poort()], tijd="2026-09-06T08:00:00Z"),
    )
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    assert BLOCK_TWO_SUBJECT not in tekst
    assert "GERAAKT" in tekst
    assert NIET_VASTGESTELD not in tekst.split("extra stap")[0]


def test_cve_checks_read_gaps_and_not_assessed_still_travel_when_block_two_is_gated(
    export_met_veld,
    knowledge,
):
    """The freshness gate replaces block 2's FINDINGS only - cve_check()
    still runs, so its read_gaps and not_assessed are exactly as complete
    as they always were ("all three lists travel"
    is not narrowed by this fix)."""
    from dataclasses import replace as _replace

    import nsmcp.after_upgrade as mod
    from nsmcp.answer import NotAssessed as _NotAssessed

    echt = mod.cve_check

    def nep(export, kennis):
        antwoord = echt(export, kennis)
        return _replace(
            antwoord,
            not_assessed=[
                *antwoord.not_assessed,
                _NotAssessed(subject="een dimensie van blok 2", reason="cve_check zegt dit zelf"),
            ],
        )

    mod.cve_check = nep
    try:
        # ledger_lines=() -> no R5 -> the freshness gate fires.
        antwoord = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=())
    finally:
        mod.cve_check = echt
    onderwerpen = [n.subject for n in antwoord.not_assessed]
    assert "een dimensie van blok 2" in onderwerpen
    subjecten = [f.subject for f in antwoord.findings]
    assert subjecten.count(BLOCK_TWO_SUBJECT) == 1


# ---------------------------------------------------------------------------
# Every test below was RED against the code before this hardening pass;
# the regression coverage below carries the failure output per finding.
#
# The ledger rows here are not hand-built: `_r0_regel()`/`_r5_regel()` shape
# them through `upgrade_measure._vorm()`, the SAME call the runner makes, so
# a test can never again pass on a ledger shape the product cannot write.
# ---------------------------------------------------------------------------

LAB = FIXTURES / "lab-export-vpx-20260826"


def _poorten(*verzoeken) -> list:
    from nsmcp.upgrade_measure import _vorm

    return _vorm({"verzoeken": list(verzoeken)})["poort"]


def _lab_config_regels() -> list:
    return (LAB / "parsed" / "runningconfig.txt").read_text(encoding="utf-8-sig").splitlines()


def _r0_regel(export_root=LAB) -> dict:
    """R0's `voormeting_vast` row with the gates the runner really queues
    for R0 (`Invoke-GjkUpgradeFase.ps1`, the R0 branch): the family counts
    and the anchor, both out of the EXPORT."""
    return _r0(
        _poorten(
            {"soort": "familietellingen", "export_root": str(export_root)},
            {"soort": "configuratie-anker-export", "export_root": str(export_root)},
        )
    )


def _r5_regel(regels=None) -> dict:
    """R5's closing row with the gates the runner really queues for R5 -
    `hostsleutel`, `secondary`, `configuratie-anker` (live) and
    `doelbuild bereikt`, and NOTHING else. There is deliberately no
    `familietellingen` request here: the R5 branch does not queue one."""
    return _r5(
        _poorten(
            {"soort": "hostsleutel", "sessie_geopend": True, "gepinde_vingerafdruk": "SHA256:abc"},
            {"soort": "secondary", "ha_node_uitvoer": "Node State: Secondary"},
            {
                "soort": "configuratie-anker",
                "exitcode": 0,
                "regels": _lab_config_regels() if regels is None else regels,
            },
            {
                "soort": "aanwezig",
                "naam": "doelbuild bereikt",
                "poorttype": "bewijs",
                "aanwezig": True,
                "bewijs": "show ns version: NetScaler NS14.1: Build 72.57.nc",
                "reden_dicht": "de teruggelezen build noemt 14.1-72.57 niet",
            },
        )
    )


def _regels_van(tekst: str, onderwerp: str) -> list:
    """Every rendered line for `onderwerp`, plus its own bewijs/reden lines."""
    uit: list = []
    verzamel = False
    for regel in tekst.splitlines():
        if regel.startswith("- "):
            verzamel = regel.startswith("- " + onderwerp + ":")
        if verzamel:
            uit.append(regel)
    return uit


# --- A hyphenated word is not a flag -----------------------------


def test_a_hyphenated_word_is_never_read_as_the_parameter():
    """`niet-name` is a Dutch compound, not a NITRO flag. Without a LEFT
    boundary on the flag pattern it parsed as `-name` - a field virtually
    every NITRO object carries - and the sentence reached an ESTABLISHED
    `GERAAKT` on a parameter no bulletin ever named."""
    zin = "Voor CVE-1: `set ns httpProfile <profiel>` op alle niet-name waarden 30 zetten"
    assert parse_extra_step(zin) is None
    assert parse_extra_step("set ns httpProfile op de niet-standaard profielen") is None


def test_a_sentence_without_a_flag_is_niet_vastgesteld_never_geraakt(export_met_veld):
    """The fourth table row, on the sentence that provoked it."""
    kennis = _knowledge(
        {
            **BULLETIN,
            "extraStapNaUpgrade": ("Voor CVE-1: `set ns httpProfile <profiel>` op alle niet-name waarden 30 zetten"),
        }
    )
    tekst = report_after_upgrade(export_met_veld, export_met_veld, kennis, ledger_lines=()).to_text()
    regels = _regels_van(tekst, "extra stap na de upgrade (CTX-DEMO-13474)")
    assert regels
    assert NIET_VASTGESTELD in regels[0]
    assert EXTRA_STEP_NO_COMMAND in "\n".join(regels)
    assert "nshttpprofile" not in "\n".join(regels)


# --- A gate that is not open is not a measurement ----------------


def test_an_anchor_gate_that_is_not_open_is_never_read_as_zero_blob_lines(export_met_veld, knowledge):
    """`upgrade_measure` writes a fail-closed `configuratie-anker` gate with
    `uitkomst='niet beoordeeld'` when no export could be loaded. Reading its
    `bewijs` anyway turned an unread R0 into `gelijk: R0=0, R5=0
    [vastgesteld]` on every blob kind - a comparison of a measurement that
    was never taken."""
    r0 = _r0(_poorten({"soort": "configuratie-anker-export", "export_root": ""}))
    ledger = (r0, _r5_regel())
    anker_poort = [p for p in r0["poort"] if p["naam"] == "configuratie-anker"][0]
    assert anker_poort["uitkomst"] == "niet beoordeeld"

    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    anker_regels = _regels_van(tekst, "configuratie-anker")
    assert ANCHOR_WORDS[2] in anker_regels[0]
    for soort in ("set ns encryptionParams", "set ns rpcNode", "-encrypted"):
        blob = _regels_van(tekst, "uitgesloten blob-regels: " + soort)
        assert blob, soort
        assert ANCHOR_WORDS[0] not in blob[0], soort
        assert "[vastgesteld]" not in blob[0], soort
        assert ANCHOR_WORDS[2] in blob[0], soort


# --- R5 writes no familietellingen gate -------------------------


def test_the_family_counts_say_precisely_that_r5_carries_no_such_gate(export_met_veld, knowledge):
    """R5's own closing row - built through the SAME `_vorm()` call the
    runner makes - carries no `familietellingen` gate at all, because the
    R5 branch of `Invoke-GjkUpgradeFase.ps1` queues none and
    `upgrade_plan.PHASE_GATES['R5']` names none. The eight lines must say
    THAT, not a generic 'niet gelezen op R0 en/of R5' that reads as if both
    sides might be at fault."""
    from nsmcp.upgrade_plan import PHASE_GATES

    assert not any("familietellingen" in g for g in PHASE_GATES["R5"])
    r5 = _r5_regel()
    assert not any(p["naam"] == "familietellingen" for p in r5["poort"])

    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, (_r0_regel(), r5)).to_text()
    for familie in FAMILIES:
        regels = _regels_van(tekst, "familietelling: " + familie)
        assert regels, familie
        assert ANCHOR_WORDS[2] in regels[0], familie
        samen = "\n".join(regels)
        assert "R5" in samen and "familietellingen" in samen, familie
        assert "niet gelezen op R0 en/of R5" not in samen, familie


# --- An unreadable-family tail cannot plant a count -------------


def test_an_unreadable_family_reason_can_never_supply_a_count(export_met_veld, knowledge):
    """`family_counts_gate` appends `; onleesbaar: <familie>: <reden>`, and
    that reason echoes the manifest's own free-form `status` string. A
    supplied export whose manifest carries `status: 'X lbvserver=7'` on some
    other resource must not thereby establish a count for `lbvserver`."""
    vergiftigd = "familietellingen: csvserver=1; onleesbaar: sslcertkey: read niet bruikbaar: X lbvserver=7"
    poort = [
        {"naam": "configuratie-anker", "type": "bewijs", "uitkomst": "open", "bewijs": "anker=" + ANKER_A, "reden": ""},
        {"naam": "familietellingen", "type": "bewijs", "uitkomst": "open", "bewijs": vergiftigd, "reden": ""},
    ]
    ledger = (_r0(poort), _r5(poort))
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger).to_text()
    lb = _regels_van(tekst, "familietelling: lbvserver")
    assert lb
    assert ANCHOR_WORDS[2] in lb[0]
    assert "7" not in lb[0]
    cs = _regels_van(tekst, "familietelling: csvserver")
    assert ANCHOR_WORDS[0] in cs[0]


# --- The two anchors come from different sources ----------------


def test_the_anchor_evidence_names_the_source_of_each_side(export_met_veld, knowledge):
    from nsmcp.after_upgrade import ANCHOR_SOURCE_R0, ANCHOR_SOURCE_R5

    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, (_r0_regel(), _r5_regel())).to_text()
    regels = "\n".join(_regels_van(tekst, "configuratie-anker"))
    assert ANCHOR_SOURCE_R0 in regels
    assert ANCHOR_SOURCE_R5 in regels


def test_a_different_anchor_says_the_two_sources_are_not_the_same_reading(export_met_veld, knowledge):
    from nsmcp.after_upgrade import ANCHOR_SOURCES_DIFFER

    afwijkend = _lab_config_regels() + ["add lb vserver later_toegevoegd HTTP 0.0.0.0 0"]
    tekst = report_after_upgrade(
        export_met_veld, export_met_veld, knowledge, (_r0_regel(), _r5_regel(afwijkend))
    ).to_text()
    regels = "\n".join(_regels_van(tekst, "configuratie-anker"))
    assert ANCHOR_WORDS[1] in regels
    assert ANCHOR_SOURCES_DIFFER in regels


# --- Smaller edge cases ------------------------------------------------------


def test_an_oversized_object_token_is_rejected_not_truncated():
    """A 70-character object name used to be TRUNCATED to 64 and turned into
    `config/nsaaaa...` - a resource the sentence never named. The VALUE has
    the same problem the other way round: a truncated expected value drives
    the GERAAKT/NIET GERAAKT comparison, so it is rejected too."""
    assert parse_extra_step("set ns " + ("a" * 70) + " -veld 30") is None
    assert parse_extra_step("set ns httpProfile -veld " + ("x" * 5000)) is None


def test_the_expected_value_is_compared_case_insensitively(export_met_veld):
    """A vendor sentence writes the value in the vendor's own casing; the
    export carries NITRO's. That is the same value, not a pending step."""
    kennis = _knowledge(
        {**BULLETIN, "extraStapNaUpgrade": ("`set ns httpProfile <profiel> -name NSHTTP_DEFAULT_PROFILE` zetten.")}
    )
    tekst = report_after_upgrade(export_met_veld, export_met_veld, kennis, ledger_lines=()).to_text()
    regels = _regels_van(tekst, "extra stap na de upgrade (CTX-DEMO-13474)")
    assert NIET_GERAAKT in regels[0]


def test_the_cve_engines_own_not_assessed_entries_are_carried_through(export_met_veld, knowledge):
    """Block 2 is `cve.cve_check` whole - its findings, its read gaps AND
    its `not_assessed`. Dropping one of the three is a silent omission in
    the one tool built to have none."""
    from dataclasses import replace as _replace

    import nsmcp.after_upgrade as mod
    from nsmcp.answer import NotAssessed as _NotAssessed

    echt = mod.cve_check

    def nep(export, kennis):
        antwoord = echt(export, kennis)
        return _replace(
            antwoord,
            not_assessed=[
                *antwoord.not_assessed,
                _NotAssessed(subject="een dimensie van blok 2", reason="cve_check zegt dit zelf"),
            ],
        )

    mod.cve_check = nep
    try:
        antwoord = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=())
    finally:
        mod.cve_check = echt
    onderwerpen = [n.subject for n in antwoord.not_assessed]
    assert "een dimensie van blok 2" in onderwerpen
    assert mod.BLOCK_ONE_SUBJECT in onderwerpen


def test_the_report_states_the_age_of_the_last_ledger_line(export_met_veld, knowledge):
    """Block 4 is entirely ledger-derived, so the age of that ledger belongs
    in the answer - the same statement `onderhoud_upgrade_stand` makes."""
    tekst = report_after_upgrade(export_met_veld, export_met_veld, knowledge, (_r0_regel(), _r5_regel())).to_text()
    assert _regels_van(tekst, "laatste ledgerregel")
    leeg = report_after_upgrade(export_met_veld, export_met_veld, knowledge, ledger_lines=()).to_text()
    regels = _regels_van(leeg, "laatste ledgerregel")
    assert regels and ANCHOR_WORDS[2] in regels[0]


def test_no_bulletin_with_an_extra_step_keeps_the_closed_vocabulary(export_met_veld):
    """`EXTRA_STEP_NONE_IN_KNOWLEDGE` is a sentence, and the outcome column
    is closed to GERAAKT/NIET GERAAKT/NIET VASTGESTELD. The sentence is the
    REASON; the outcome stays inside the vocabulary."""
    geen_stap = _knowledge(BULLETIN_ZONDER_STAP)
    antwoord = report_after_upgrade(export_met_veld, export_met_veld, geen_stap, ledger_lines=())
    stap = [b for b in antwoord.findings if b.subject == "extra stap na de upgrade"]
    assert len(stap) == 1
    assert stap[0].outcome in (GERAAKT, NIET_GERAAKT, NIET_VASTGESTELD)
    assert stap[0].reason == EXTRA_STEP_NONE_IN_KNOWLEDGE


def test_the_two_na_upgrade_fixtures_carry_the_manifest_fields_the_collector_writes():
    """The module docstring claims these fixtures match the real
    collector's shape. The real collector writes `httpStatus` and a
    `payloadSha256` per resource (measured on
    `tests/fixtures/lab-export-vpx-20260826`); a fixture that carries
    neither does not match that shape, and a hash nobody recomputes is not
    a hash. Object hashes cover the exact bytes, as `Export._object_payload`
    requires; running-config text has its own separate normalization rule."""
    import hashlib as _hashlib
    import json as _json

    for naam in ("na-upgrade-met-veld", "na-upgrade-zonder-veld"):
        wortel = FIXTURES / naam
        manifest = _json.loads((wortel / "export-manifest.json").read_text(encoding="utf-8"))
        for resource, vermelding in manifest["resources"].items():
            assert "httpStatus" in vermelding, (naam, resource)
            bestand = wortel / "objects" / (vermelding["propertyName"] + ".json")
            rauw = bestand.read_bytes()
            verwacht = _hashlib.sha256(rauw).hexdigest().upper()
            assert vermelding["payloadSha256"] == verwacht, (naam, resource)
