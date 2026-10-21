"""The disclosure knob: how much the answer may reveal to the reading model.

Design: the regression coverage below
The filter is COMPUTED, never done by the model; the analysis does not change.

All tests up to the "INTEGRATION" section render a HAND-BUILT Answer
fixture - valuable to prove `_limit()`/`_minimal()` in isolation, but they
could never see the structural cause of names leaking through free text:
none of these fixtures ever comes from the REAL engine. The INTEGRATION
section therefore really runs `expiry.what_expires`/`impact.what_breaks`/
`action.what_to_do` against a real `Export` on disk (`load_export`), and
renders that result - exactly the path mcp_server.py also walks.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from conftest import maintenance_config, provenance_dir_for, record_collected, seal_manifest

from nsmcp import disclosure as disclosure_module
from nsmcp.action import what_to_do
from nsmcp.answer import Answer, Certainty, Finding, ReadGap, stamp_data
from nsmcp.disclosure import (
    Disclosure,
    PseudonymAsInput,
    PseudonymSpaceExhausted,
    PseudonymTableBroken,
    load_disclosure,
    names_from_export,
    render,
)
from nsmcp.expiry import what_expires
from nsmcp.export import load_export
from nsmcp.impact import ImpactAnswer, candidate_finding, what_breaks
from nsmcp.knowledge import Knowledge


def _answer() -> Answer:
    return Answer(
        question="wat breekt er als wildcard_gjk verloopt",
        findings=[
            Finding(
                subject="LB_VS_PORTAAL",
                outcome="valt uit als wildcard_gjk verloopt",
                certainty=Certainty.ESTABLISHED,
                evidence="binding wildcard_gjk -> LB_VS_PORTAAL via SNI",
            )
        ],
        read_gaps=[ReadGap(source="config/sslvserver", reason="read niet bruikbaar: FAILED")],
        knowledge_date="2026-08-16",
        knowledge_age_days=10,
        data_date="2026-08-25",
        data_age_days=1,
        data_target="lab",
    )


def test_load_disclosure_knows_the_three_settings():
    assert load_disclosure("volledig") is Disclosure.FULL
    assert load_disclosure("beperkt") is Disclosure.LIMITED
    assert load_disclosure("minimaal") is Disclosure.MINIMAL


def test_unknown_setting_refuses_without_fallback():
    """The same discipline as load_profile: a typo must never silently yield
    a DIFFERENT disclosure than the operator meant."""
    with pytest.raises(ValueError) as err:
        load_disclosure("open")
    assert "volledig" in str(err.value)


def test_full_renders_byte_identical_to_to_text():
    """The default setting changes NOTHING - we are open, shielding is a choice."""
    a = _answer()
    assert render(a, Disclosure.FULL, tool="certificaat_wat_breekt_er") == a.to_text()


def test_limited_no_real_object_name_reaches_the_answer(tmp_path):
    text = render(
        _answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=("wildcard_gjk",),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "wildcard_gjk" not in text
    assert "LB_VS_PORTAAL" not in text
    assert "object-" in text


def test_limited_keeps_the_numbers_and_the_honesty(tmp_path):
    """The value never sat in the names: age, read gaps and severity remain."""
    text = render(
        _answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=("wildcard_gjk",),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "Gegevens van 2026-08-25" in text
    assert "NIET VASTGESTELD" in text
    assert "config/sslvserver" in text  # a resource path is not an object name


def test_limited_pseudonym_table_is_local_and_correct(tmp_path):
    """The storage direction follows the design (par. 3) - the file carries
    PSEUDONYM -> REAL NAME, not the other way around. Against the old shape
    (before the flip) this test fails: there the real names sit as KEY and
    the pseudonyms as VALUE, exactly reversed."""
    import json

    path = tmp_path / "tabel.json"
    render(
        _answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=("wildcard_gjk",),
        pseudonym_table_path=path,
    )
    table = json.loads(path.read_text(encoding="utf-8"))
    assert "LB_VS_PORTAAL" in table.values() and "wildcard_gjk" in table.values()
    assert all(p.startswith("object-") for p in table.keys())


def test_limited_pseudonyms_are_stable_across_calls(tmp_path):
    """Two answers about the same object must carry the same pseudonym,
    otherwise the operator cannot relate them to each other."""
    path = tmp_path / "tabel.json"
    first = render(
        _answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=("wildcard_gjk",),
        pseudonym_table_path=path,
    )
    second = render(
        _answer(),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=("wildcard_gjk",),
        pseudonym_table_path=path,
    )
    assert first == second


def test_limited_overlapping_names_longest_first(tmp_path):
    """Masking lesson: 'LB_VS_PORTAAL_2' must be replaced as a WHOLE, not as
    'LB_VS_PORTAAL' + '_2'."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="LB_VS_PORTAAL",
                outcome="x",
                certainty=Certainty.ESTABLISHED,
                evidence="raakt LB_VS_PORTAAL_2 ook",
            ),
            Finding(subject="LB_VS_PORTAAL_2", outcome="y", certainty=Certainty.ESTABLISHED, evidence="b"),
        ],
    )
    text = render(a, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", pseudonym_table_path=tmp_path / "tabel.json")
    assert "LB_VS_PORTAAL" not in text
    assert "_2" not in text


def test_limited_a_one_character_caller_name_does_not_shred_the_answer(tmp_path):
    """MEASURED: `_limit()` added the
    caller-supplied name to an unbounded alternation with no minimum length
    and no word boundary. A one-character `caller_name` like "e" then
    replaced every bare 'e' anywhere in the text - "certificaat_klaarzetten"
    came back as "c(onbekende naam uit de vraag)rtificaat_klaarz(onbekende
    naam uit de vraag)tt(onbekende naam uit de vraag)n". The fix must still
    mask the caller's value should it stand on its own (fail safe: a name
    the export cannot vouch for is masked, never leaked), while leaving
    ordinary product text alone."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="certificaat_klaarzetten: gewijzigd",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="e",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "certificaat_klaarzetten: gewijzigd" in text
    assert "onbekende naam uit de vraag" not in text


def test_limited_a_one_character_caller_name_alone_is_still_masked(tmp_path):
    """The other side of the same guard: a one-character name that DOES
    stand on its own (bounded by non-word characters on both sides) is a
    value this product cannot vouch for, and must still be replaced -
    never echoed verbatim just because it is short."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="naam uit de vraag: e",
                certainty=Certainty.ESTABLISHED,
                evidence="b",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="e",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "naam uit de vraag: (onbekende naam uit de vraag)" in text


def test_a_wildcard_certificate_name_is_masked(tmp_path):
    """MEASURED: `\\b` demands an actual WORD
    character on the side it tests. A wildcard certificate name - the most
    ordinary NetScaler certificate SHAPE there is - starts with '*', a
    NON-word character, so `\\b` never matches immediately before it when
    it opens a line or follows a space: the old
    `rf"\\b{re.escape(n)}\\b"` in `_replacement_pattern()` therefore let
    `caller_name="*.gjk.nl"` straight through, unmasked, in the exact
    ordinary case a NetScaler certnaam takes. Fixed with `(?<!\\w)` /
    `(?!\\w)` lookarounds, which do not require a word character on the
    far side - only the ABSENCE of one where the match starts or ends."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="certificaat *.gjk.nl klaargezet",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="*.gjk.nl",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "*.gjk.nl" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_a_certificate_name_with_a_trailing_dot_is_masked(tmp_path):
    """Same guard, the mirrored edge: a name that ENDS on a non-word
    character ('.') is not followed by a word character either when it
    closes a sentence or sits before a space - `\\b` never matched there,
    the lookaround does."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="certificaat gjk.nl. klaargezet",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="gjk.nl.",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "gjk.nl." not in text, text
    assert "onbekende naam uit de vraag" in text


def test_a_name_starting_with_a_hyphen_is_masked(tmp_path):
    """Third measured leaking form: a name that STARTS on a non-word
    character ('-')."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="doel -lab niet bereikbaar",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="-lab",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "-lab" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_a_multi_character_name_embedded_in_a_longer_word_is_not_masked(tmp_path):
    """The lookaround swap must not overcorrect: `(?<!\\w)`/`(?!\\w)` are
    looser than `\\b` only in the three cases measured above (they do not
    require an actual word character on the far side); they must stay just
    as strict as `\\b` INSIDE an ordinary word. A caller name embedded on
    BOTH sides by word characters - not only the single-character
    "certificaat_klaarzetten" case item 9 was about - must still pass
    through unmasked."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="certificaat_klaarzetten: instalabelwissel gelukt",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="lab",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "certificaat_klaarzetten: instalabelwissel gelukt" in text
    assert "onbekende naam uit de vraag" not in text


def test_wildcard_name_is_masked_inside_a_longer_identifier(tmp_path):
    """MEASURED: the previous fix
    applied `(?<!\\w)`/`(?!\\w)` UNCONDITIONALLY on both sides. That is not
    a superset of `\\b...\\b`: at a `\\b` transition one side of the match
    HAS a word character, which an unconditional lookaround forbids on
    exactly that side. `caller_name="*.gjk.nl"` embedded right after a
    word character ("ssl_") reproduced the leak the previous round fixed
    for the standalone case - the underscore before `*` failed
    `(?<!\\w)`, so the whole branch never matched and the name came back
    literal. Fixed by applying `(?<!\\w)` only when the name ITSELF starts
    with a word character - `*.gjk.nl` starts with `*`, so that side now
    carries no guard at all."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="certificaat ssl_*.gjk.nl omgezet",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="*.gjk.nl",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "*.gjk.nl" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_trailing_dot_name_is_masked_inside_a_longer_identifier(tmp_path):
    """Same class as above, mirrored edge: `caller_name="gjk.nl."` ends on
    a non-word character ('.'), so the previous round's unconditional
    `(?!\\w)` on the right side failed against the 'c' of "gjk.nl.crt" and
    the name leaked literal. Fixed: no right-side guard for a name that
    itself ends on a non-word character."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="bestand gjk.nl.crt geplaatst",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="gjk.nl.",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "gjk.nl." not in text, text
    assert "onbekende naam uit de vraag" in text


def test_hyphen_prefixed_name_is_masked_inside_a_longer_identifier(tmp_path):
    """Third measured narrowing regression: `caller_name="-lab"` starts on
    '-', a non-word character. The previous round's unconditional
    `(?<!\\w)` on the left failed against the 'k' of "gjk-lab" and the
    name leaked literal. Fixed: no left-side guard for a name that itself
    starts on a non-word character."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="doel gjk-lab niet bereikbaar",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="-lab",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "-lab" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_alphanumeric_name_lab1_standalone_is_masked(tmp_path):
    """Sanity pin alongside the three regressions above: a name that
    starts AND ends on a word character behaves the same before and after
    R1 (both guards apply, exactly like the item-9 case) - digits count as
    `\\w` too, so a trailing digit must not accidentally drop a guard."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="omgeving lab1 bijgewerkt",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="lab1",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "lab1" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_alphanumeric_name_1lab_standalone_is_masked(tmp_path):
    """Same sanity pin, name starting on a digit instead of a letter - a
    leading digit must not accidentally drop the left-side guard either."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="omgeving 1lab bijgewerkt",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="1lab",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "1lab" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_a_name_with_regex_metacharacters_is_masked(tmp_path):
    """Confirms `re.escape()` still applies to the whole name after the
    per-side rewrite: an unescaped "a(b)+c" would compile as "a", one or
    more capture groups of "b", then "c" - a pattern that does NOT match
    the literal text "a(b)+c" (there is no run of bare 'b' characters
    right after the 'a'). If escaping were ever lost while reworking this
    function, this name would stop being masked."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="waarde a(b)+c geplaatst",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="a(b)+c",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "a(b)+c" not in text, text
    assert "onbekende naam uit de vraag" in text


def test_empty_caller_name_produces_no_pattern(tmp_path):
    """Must produce NO pattern: the empty string was already treated as
    "no name" before this round (`if caller_name` is False for ""), pinned
    here alongside the whitespace-only and punctuation-only cases below so
    the three sit together as one rule."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="geen backup jonger dan 7 dagen - en geen buildboom",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "geen backup jonger dan 7 dagen - en geen buildboom" in text
    assert "onbekende naam uit de vraag" not in text


def test_whitespace_only_caller_name_produces_no_pattern(tmp_path):
    """MEASURED: `render()` had no `.strip()` on
    `caller_name`, so a whitespace-only value (a single space) was truthy,
    not in `extra_names`, and became `invented_name` - `_replacement_
    pattern()` then compiled a bare, unguarded space into the alternation.
    That space has no word character on either side, so neither lookaround
    ever applies to IT, but the guard still checks the characters OUTSIDE
    the match: it only fires where the space itself sits directly between
    two other non-word characters (a colon and a hyphen here, an ordinary
    Dutch way to write "value: - not yet known") - most inter-word spaces
    (word char on at least one side) stay safe, which is exactly why an
    unqualified "every space becomes a placeholder" claim would overstate
    the bug. `extra_names` already filters blank entries with `.strip()`
    (see the collection in `_collect_names()`); `caller_name` must agree."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="waarde: - niet bepaald",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name=" ",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "waarde: - niet bepaald" in text, text
    assert "onbekende naam uit de vraag" not in text, text


def test_punctuation_only_caller_name_produces_no_pattern(tmp_path):
    """A caller
    name with NO word character at all is not a name and gets no pattern -
    treated exactly like a missing name. A NetScaler object name must
    start with a letter (`handelen._NAME` is
    `[A-Za-z][A-Za-z0-9._-]{0,62}`), so a string of pure punctuation cannot
    identify an appliance object; there is nothing to protect, and masking
    on it only forges placeholders into ordinary product text.

    Each ordinary text below DELIBERATELY carries the punctuation form
    itself, standing alone (spaces on both sides) - without that, a bare,
    unguarded literal pattern for e.g. "-" would simply find nothing to
    match in text that never contains a bare hyphen, and this test would
    pass whether or not the punctuation rule exists at all. See the
    dedicated shredding test below for the exact measured
    sentence with "-"."""
    cases = (
        ("-", "geen backup jonger dan 7 dagen - en geen buildboom"),
        ("*", "patroon * dekt alles"),
        ("--", "optie -- genegeerd"),
    )
    for i, (punct, outcome) in enumerate(cases):
        a = Answer(
            question="v",
            findings=[
                Finding(
                    subject="uitkomst",
                    outcome=outcome,
                    certainty=Certainty.ESTABLISHED,
                    evidence="schrijfscript",
                    subject_is_name=False,
                )
            ],
        )
        text = render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_klaarzetten",
            caller_name=punct,
            pseudonym_table_path=tmp_path / f"tabel-{i}.json",
        )
        assert outcome in text, (punct, text)
        assert "onbekende naam uit de vraag" not in text, (punct, text)


def test_punctuation_only_caller_name_leaves_an_ordinary_sentence_unchanged(tmp_path):
    """The exact shredding class from item 9, reopened by the unconditional
    lookaround swap: `caller_name="-"` matches between two non-word
    characters (a plain space on both sides of the hyphen in ordinary
    Dutch text), where `\\b` never matched there at all. Without the
    punctuation rule, this ordinary sentence comes back with a forged
    placeholder inserted where the sentence's own hyphen sits."""
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="geen backup jonger dan 7 dagen - en geen buildboom",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="certificaat_klaarzetten",
        caller_name="-",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "geen backup jonger dan 7 dagen - en geen buildboom" in text, text
    assert "onbekende naam uit de vraag" not in text, text


def test_next_free_pseudonym_fails_closed_instead_of_hanging(monkeypatch):
    """MEASURED: `_collides_with_real_names()`
    tests a candidate as a substring of a real name in EITHER direction, so
    a real name that is itself a substring of the fixed literal "object-"
    prefix ("o" qualifies - it sits right there in "object") collides with
    EVERY candidate `_next_free_pseudonym()` could ever generate; the
    number changes, the colliding prefix does not. The old `while True`
    therefore never returned for such a name - this is the DIRECT unit
    test on the generator itself, not only on a caller that happens to
    reach it. `_MAX_PSEUDONYM_ATTEMPTS` is monkeypatched small so this test
    stays fast and can never hang the suite regardless of the bound's real
    production value."""
    monkeypatch.setattr(disclosure_module, "_MAX_PSEUDONYM_ATTEMPTS", 5)
    with pytest.raises(PseudonymSpaceExhausted):
        disclosure_module._next_free_pseudonym(1, {"o"})


def test_render_fails_closed_on_a_colliding_extra_name(tmp_path, monkeypatch):
    """The same measurement through the real caller path: no malformed
    allowlist needed, and no caller-supplied name either - a plain,
    CORRECTLY TYPED `extra_names=("o",)` (exactly the shape
    `mcp_server._write_names()` and `names_from_export()` both hand to
    `render()` normally) reaches `_next_free_pseudonym()` unchanged and
    used to hang there. `mcp_server._write_names()`'s allowlist type check
    closes only the ONE calling path that
    could hand it a malformed string - it cannot and does not close this
    path, which never was malformed to begin with. The bound therefore has
    to sit in the generator itself (see `_next_free_pseudonym` above), and
    this is the proof that `render()` now fails closed through it instead
    of hanging."""
    monkeypatch.setattr(disclosure_module, "_MAX_PSEUDONYM_ATTEMPTS", 5)
    a = Answer(question="v", findings=[])
    with pytest.raises(PseudonymSpaceExhausted):
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("o",),
            pseudonym_table_path=tmp_path / "tabel.json",
        )


def test_minimal_no_object_line_reaches_the_answer():
    text = render(_answer(), Disclosure.MINIMAL, tool="certificaat_wat_breekt_er", extra_names=("wildcard_gjk",))
    assert "wildcard_gjk" not in text
    assert "LB_VS_PORTAAL" not in text
    assert "object-" not in text  # no pseudonyms either: ONLY aggregates


def test_minimal_carries_the_counts_and_the_stamps():
    text = render(_answer(), Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "1 bevinding(en)" in text
    assert "1 leesgat(en)" in text
    assert "Gegevens van 2026-08-25" in text
    assert "Kennisbasis van 2026-08-16" in text


def test_minimal_worst_remaining_term_is_derived_deterministically():
    a = Answer(
        question="wat verloopt er",
        findings=[
            Finding(subject="a", outcome="verloopt over 20 dagen", certainty=Certainty.ESTABLISHED, evidence="b"),
            Finding(subject="b", outcome="verloopt over 200 dagen", certainty=Certainty.ESTABLISHED, evidence="b"),
        ],
    )
    text = render(a, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    assert "20 dagen" in text
    assert "200 dagen" not in text


def test_minimal_without_derivable_term_says_so_honestly():
    text = render(_answer(), Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "niet afleidbaar" in text


def test_minimal_question_line_carries_no_argument():
    """The question line contains the certnaam from the argument; in minimal
    only the tool name remains."""
    text = render(_answer(), Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert text.splitlines()[0] == "Vraag: certificaat_wat_breekt_er (stand: minimaal)"


def test_minimal_no_double_blank_line_before_the_stamps():
    """The old `splitlines()[1:]` left two blank lines between the last
    bullet and 'Kennisbasis:' (see _minimal in disclosure.py for the
    precise count)."""
    text = render(_answer(), Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "\n\n\n" not in text


# ---------------------------------------------------------------------------
# INTEGRATION: the REAL engine, not a hand-built Answer fixture.
# See the module docstring for why this is the section that could really
# see the leaks.
# ---------------------------------------------------------------------------

_CERT = "wildcard_gjk"


def _real_knowledge() -> Knowledge:
    return Knowledge(version="test", date="2026-08-16", age_days=1, missing=False)


def _real_export(tmp_path: Path, bindings=None, certs=None, cert_status="OK", hash_matches=True):
    """A REAL export on disk, read through `load_export` - the same shape as
    tests/test_mcp_server.py::_full_export_dir, built separately here so
    this test file gains no dependency on another test module.

    FILE NAME/SHAPE: `objects/sslcertkey.json` (no "config_" prefix) and
    `bindings/sslvserver_sslcertkey_binding.by-parent.json` in the
    by-parent shape - see `tests/fixtures/lab-export-vpx-20260826/`.
    `bindings` remains a flat `{vservername: [binding, ...]}` shape for
    the CALLER; this function translates it to the real by-parent shape.
    """
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir(parents=True)
    if certs is None:
        certs = [{"certkey": _CERT, "daystoexpiration": 9, "status": "Valid"}]
    (m / "objects" / "sslcertkey.json").write_text(json.dumps({"sslcertkey": certs}), encoding="utf-8")
    if bindings is None:
        bindings = {
            "LB_VS_PORTAAL": [{"certkeyname": _CERT, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
        }
    by_parent = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {"parentName": name, "outcome": "OK", "data": {"sslvserver_sslcertkey_binding": items}}
            for name, items in bindings.items()
        ],
    }
    # De OBJECTBRON van de parents. De echte collector schrijft die altijd
    # (`config/sslvserver` in het manifest, `objects/sslvserver.json` op
    # schijf); zonder die bron is de parentlijst niet te kruiscontroleren en
    # meldt de motor daar terecht een leesgat over.
    (m / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": n} for n in bindings]}), encoding="utf-8"
    )
    raw = json.dumps(by_parent)
    (m / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    real_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/sslcertkey": {"status": cert_status},
                    "config/sslvserver": {"status": "OK"},
                },
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": real_hash if hash_matches else "0" * 64
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    return load_export(m)


def _no_name_leaks(text: str, names: tuple[str, ...]) -> None:
    leaked = [n for n in names if n in text]
    assert not leaked, f"objectnaam/-namen lekken door de openheidsnaad: {leaked}\n---\n{text}"


def test_INTEGRATION_certificaat_wat_moet_ik_doen_limited_leaks_no_export_name(tmp_path):
    """The happy path of certificaat_wat_moet_ik_doen puts the affected virtual servers
    in FREE TEXT ("2. Koppel het om op: LB_VS_PORTAAL."). Moreover,
    `what_to_do()` returns a bare Answer (not an ImpactAnswer), so
    affected_vservers does not even exist on THIS answer - the old name
    collection had LITERALLY NOTHING for this tool except the certnaam
    itself."""
    export = _real_export(tmp_path)
    knowledge = _real_knowledge()
    answer = what_to_do(what_breaks(export, knowledge, _CERT), knowledge, _CERT)
    assert "LB_VS_PORTAAL" in answer.findings[0].outcome  # premise: the name really sits in free text

    names = names_from_export(export) + (_CERT,)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_moet_ik_doen",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)
    assert "object-" in text


def test_INTEGRATION_what_breaks_limited_read_gap_source_leaks_no_export_name(tmp_path):
    """The read-gap variant that would have caught the leak -
    certkeyname=None yields an unassessable binding; impact.py's read-gap
    statement puts the vserver name in ReadGap.SOURCE
    ("...vservername=LB_VS_PORTAAL"), not in .reason. No finding carries
    this name (the binding never becomes a Finding - it is unassessed), so
    this proves the source itself is rewritten, not that the name happened
    to be covered through another field already."""
    export = _real_export(
        tmp_path,
        bindings={
            "LB_VS_PORTAAL": [{"certkeyname": None, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
        },
    )
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    assert answer.findings == []  # premise: no finding carries the name
    assert any("LB_VS_PORTAAL" in g.source for g in answer.read_gaps)  # premise: the source does carry it

    names = names_from_export(export) + (_CERT,)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)


def test_INTEGRATION_certificaat_wat_moet_ik_doen_limited_read_gap_source_from_action_leaks_no_export_name(tmp_path):
    """Second path - action.py puts the vserver name (from the finding
    subject) directly as ReadGap.source as soon as impact.py delivers a
    NOT_ESTABLISHED finding (here: the ca flag is missing on the
    binding)."""
    export = _real_export(
        tmp_path,
        bindings={"LB_VS_PORTAAL": [{"certkeyname": _CERT, "vservername": "LB_VS_PORTAAL", "snicert": False}]},
    )
    knowledge = _real_knowledge()
    answer = what_to_do(what_breaks(export, knowledge, _CERT), knowledge, _CERT)
    assert any("LB_VS_PORTAAL" in g.source for g in answer.read_gaps)  # premise

    names = names_from_export(export) + (_CERT,)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_moet_ik_doen",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)


def test_INTEGRATION_certificaat_wat_verloopt_er_limited_leaks_no_export_name(tmp_path):
    export = _real_export(tmp_path)
    knowledge = _real_knowledge()
    answer = what_expires(export, knowledge, 90)
    names = names_from_export(export)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_verloopt_er",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)


def test_INTEGRATION_certificaat_wat_moet_ik_doen_minimal_leaks_no_export_name(tmp_path):
    """The same engine call as the LIMITED variant above, now in the
    strictest setting: no names AND no pseudonyms."""
    export = _real_export(tmp_path)
    knowledge = _real_knowledge()
    answer = what_to_do(what_breaks(export, knowledge, _CERT), knowledge, _CERT)
    names = names_from_export(export) + (_CERT,)
    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_moet_ik_doen")
    _no_name_leaks(text, names)
    assert "object-" not in text


def test_INTEGRATION_what_breaks_minimal_read_gap_leaks_no_export_name(tmp_path):
    export = _real_export(
        tmp_path,
        bindings={
            "LB_VS_PORTAAL": [{"certkeyname": None, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
        },
    )
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    names = names_from_export(export) + (_CERT,)
    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    _no_name_leaks(text, names)
    assert "object-" not in text


def test_INTEGRATION_certificaat_wat_verloopt_er_minimal_leaks_no_export_name(tmp_path):
    export = _real_export(tmp_path)
    knowledge = _real_knowledge()
    answer = what_expires(export, knowledge, 90)
    names = names_from_export(export)
    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    _no_name_leaks(text, names)
    assert "object-" not in text


def test_CODERING_unreadable_text_encoding_is_refused_with_path_not_content(tmp_path):
    """A table file that is not valid UTF-8 raises `UnicodeDecodeError` from
    `read_text`, NOT `OSError` - elsewhere in the codebase (target.py,
    start.py) both are caught together, but the table loader only caught
    `OSError`, so an encoding error escaped as a generic masked error
    WITHOUT the path the operator needs. Same discipline as every other
    table refusal: `PseudonymTableBroken` with the path, no file content
    in the message, and the file itself stays byte-identical."""
    path = tmp_path / "tabel.json"
    path.write_bytes(b"\xff\xfeGEHEIME_INHOUD_NIET_TONEN")
    before_bytes = path.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )

    message = str(err.value)
    assert str(path) in message
    assert "GEHEIME_INHOUD_NIET_TONEN" not in message  # no raw file content
    assert "0xff" not in message and "0xfe" not in message  # no raw bytes either

    after_bytes = path.read_bytes()
    assert after_bytes == before_bytes, "de vertaaltabel is gewijzigd ondanks de weigering"
    assert hashlib.sha256(after_bytes).hexdigest() == before_hash


def test_CONCURRENCY_table_lock_prevents_colliding_pseudonyms(tmp_path):
    """The three question tools can read-enrich-write the same pseudonym
    table concurrently. Without the module-level lock in _load_table()
    (disclosure.py), concurrent writers could overwrite each other's new
    assignments or give two names the same number."""
    path = tmp_path / "tabel.json"
    names = tuple(f"vserver-{i:03d}" for i in range(20))
    errors: list[Exception] = []

    def work(name: str) -> None:
        try:
            render(
                Answer(
                    question="v",
                    findings=[Finding(subject=name, outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")],
                ),
                Disclosure.LIMITED,
                tool="certificaat_wat_breekt_er",
                pseudonym_table_path=path,
            )
        except Exception as exc:  # noqa: BLE001 - the point of the test is: none at all
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in names]
    for d in threads:
        d.start()
    for d in threads:
        d.join()

    assert errors == []
    table = json.loads(path.read_text(encoding="utf-8"))
    # The table maps pseudonym -> real name - the 20 real names thus sit in
    # the VALUES, not the keys, and every name must occur exactly once (no
    # lost update, no two names sharing the same pseudonym).
    assert set(table.values()) == set(names)
    assert len(table) == len(names)


# ---------------------------------------------------------------------------
# The pseudonym-table integrity tests below: each one was adversarially
# proven to fail before the corresponding repair landed here. See
# the regression coverage below for the RED output per test.
# ---------------------------------------------------------------------------


def test_identity_table_is_refused_the_exact_review_case(tmp_path):
    """The exact failure case: a pre-existing, syntactically valid,
    semantically broken table (`{"ZEER_GEHEIM_VSERVER":
    "ZEER_GEHEIM_VSERVER"}`) must be refused fail-closed - not silently
    accepted with the real name leaking in question/subject/outcome/
    evidence."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"ZEER_GEHEIM_VSERVER": "ZEER_GEHEIM_VSERVER"}), encoding="utf-8")

    a = Answer(
        question="wat breekt er als ZEER_GEHEIM_VSERVER verloopt",
        findings=[
            Finding(
                subject="ZEER_GEHEIM_VSERVER",
                outcome="raakt ZEER_GEHEIM_VSERVER",
                certainty=Certainty.ESTABLISHED,
                evidence="binding op ZEER_GEHEIM_VSERVER",
            )
        ],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("ZEER_GEHEIM_VSERVER",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)


# Deterministic race without gambling on OS scheduling, and DELIBERATELY
# independent of any implementation detail of the table loader itself (it
# must also work against the unrepaired version): the hook sits in
# the worker, not in nsmcp/disclosure.py. Process A monkeypatches
# `Path.read_text` so that the call reading the table from this one path
# waits briefly AFTER the real read and BEFORE the rest of the processing
# - exactly the window between "read" and "write" where the historical
# lost update sat. The table is created up front as an empty JSON object,
# so that EVEN the very first process is guaranteed to go through
# `path.read_text()` (otherwise there would be nothing to delay for a
# nonexistent file).
_DELAYED_READ_WORKER = """
import os
import sys
import time
from pathlib import Path

name = sys.argv[1]
path = Path(sys.argv[2])

delay = os.environ.get("NSMCP_OPENHEID_TESTHAAK_VERTRAGING_S")
if delay:
    _original_read_text = Path.read_text

    def _delayed_read_text(self, *a, **kw):
        result = _original_read_text(self, *a, **kw)
        if self == path:
            time.sleep(float(delay))
        return result

    Path.read_text = _delayed_read_text

from nsmcp.answer import Answer, Finding, Certainty
from nsmcp.disclosure import Disclosure, render

answer = Answer(
    question="v",
    findings=[
        Finding(subject=name, outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")
    ],
)
render(answer, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", pseudonym_table_path=path)
"""


_OBJECT_NUMBER_PATTERN = re.compile(r"^object-\d+$")


def _real_names_from_table(table: dict[str, str]) -> set[str]:
    """Works for BOTH storage directions (before and after the repair): the
    side that does not (fully) follow the pseudonym pattern 'object-NN'
    carries the real names. That lets the test reuse the same assertion for
    the RED probe against the old direction and the repair (new
    direction)."""
    if table and all(_OBJECT_NUMBER_PATTERN.match(k) for k in table):
        return set(table.values())
    return set(table.keys())


# The name-neutrality guard that used to sit here now lives at the product
# surface, not at the disclosure seam: tests/test_product_surface.py,
# function test_name_neutrality_no_product_name_in_code.


# ---------------------------------------------------------------------------
# The FOUTLEK_* tests (error-leak, adversarially proven with a render
# probe, LEK=True): "never leaks real names" was untrue at the MESSAGE
# level. PseudonymTableBroken refused correctly, but the error text quoted
# the suspicious key/value LITERALLY - and mask_error() in mcp_server.py
# deliberately passes a ToolError (so also PseudonymTableBroken) UNCHANGED
# to the AI client. Exactly in the settings that had to hide names, the
# error path carried them out unmasked.
#
# The repair sits at the SOURCE: no PseudonymTableBroken message may carry
# literal table content (keys or values). Entries are referenced by
# position (1-based, file order) plus a recognizable reason category -
# usable for the operator who has the table, unreadable as a name for the
# reading model. Every test below covers one refusal category and asserts
# BOTH sides: the literal table content is ABSENT, the position and the
# reason category are PRESENT. The fail-closed behavior itself (refuse,
# never overwrite the table) does not change and stays covered by the
# existing tests above.
# ---------------------------------------------------------------------------


def test_FOUTLEK_real_name_as_key_does_not_leak_in_the_error_text(tmp_path):
    """The core of the finding: a real export name as the suspicious KEY
    (the old-direction shape). The refusal itself was already correct
    (test_old_storage_direction_is_refused above); this test guards
    that the ERROR TEXT no longer quotes that name."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"LB_VS_PORTAAL": "object-01"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "LB_VS_PORTAAL" not in message
    assert "wildcard_gjk" not in message
    assert str(path) in message  # the path remains: that is repair information, not a name
    assert "vermelding 1" in message


def test_FOUTLEK_real_name_as_value_does_not_leak_in_the_error_text(tmp_path):
    """The value variant: the duplicate-assignment refusal was the only
    raise site that put VALUES (real names!) in the message
    (`...dezelfde echte naam ({dubbel})...`). Two pseudonyms to the same
    real name -> refuse, but the name itself stays out of the text; the
    message points at the entries by position."""
    path = tmp_path / "tabel.json"
    path.write_text(
        json.dumps({"object-01": "LB_VS_PORTAAL", "object-02": "LB_VS_PORTAAL"}),
        encoding="utf-8",
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "LB_VS_PORTAAL" not in message
    assert "dezelfde echte naam" in message
    assert "vermeldingen 1 en 2" in message


def test_FOUTLEK_identity_mapping_names_position_not_content(tmp_path):
    """Identity category. The key must follow the object-NN pattern to reach
    this raise site at all, but even a pseudonym-shaped key is TABLE
    CONTENT and stays out of the message."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-05": "object-05"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "object-05" not in message
    assert "vermelding 1" in message
    assert "identiteitsafbeelding" in message


def test_FOUTLEK_namespace_collision_real_name_in_pseudonym_does_not_leak(tmp_path):
    """Collision direction 1: the real name is a substring of the pseudonym
    ("bject-01" sits literally inside "object-01"). The message names
    position and category, neither of the two strings."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "bject-01"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "object-01" not in message
    assert "bject-01" not in message
    assert "vermelding 1" in message
    assert "botst" in message


def test_FOUTLEK_namespace_collision_pseudonym_in_real_name_does_not_leak(tmp_path):
    """Collision direction 2 (the mirror): the pseudonym is a substring of
    its own real name - the exact FR3 class, now at the message level."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "object-01-GEHEIME-vserver"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "object-01" not in message  # also covers the longer name containing it
    assert "GEHEIME" not in message
    assert "vermelding 1" in message
    assert "botst" in message


def test_FOUTLEK_pattern_error_trailing_newline_does_not_leak(tmp_path):
    """Pattern-error category (now at the message level): a
    key with a trailing newline is refused without the key itself
    appearing in the message; the pattern NAME 'object-NN' (a description,
    not table content) remains recognizable as the category."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01\n": "GEHEIM_WAARDE_X"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "object-01" not in message
    assert "GEHEIM_WAARDE_X" not in message
    assert "vermelding 1" in message
    assert "object-NN" in message


def test_FOUTLEK_old_direction_table_does_not_leak_the_real_name(tmp_path):
    """Old-direction category: a table with the real name as key (the old
    storage shape). The REVERSED-direction hint remains (it helps the
    operator), the name itself disappears from the message."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"GEHEIME_ECHTE_NAAM": "object-01"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "GEHEIME_ECHTE_NAAM" not in message
    assert "vermelding 1" in message
    assert "OMGEKEERDE richting" in message


def test_FOUTLEK_empty_value_does_not_name_the_key(tmp_path):
    """Empty-value category: the old message quoted the KEY of the row
    ('draagt bij pseudoniem {key!r}...'). That reference too goes by
    position."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "   "}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "object-01" not in message
    assert "vermelding 1" in message
    assert "geen bruikbare echte naam" in message


def test_FOUTLEK_invalid_key_does_not_quote_the_key(tmp_path):
    """Invalid-key category: an empty key used to put the quoted repr ('')
    in the message - also a quotation of table content."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"": "GEHEIM_X"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "''" not in message
    assert "GEHEIM_X" not in message
    assert "vermelding 1" in message
    assert "ongeldige pseudoniemsleutel" in message


# ---------------------------------------------------------------------------
# The PSEUDONIEMINVOER_* tests: the two sides of the narrow gate between
# "the table is broken" and "the QUESTION was asked with a pseudonym". The
# full measurement behind this finding, and the real-session proof, sit in
# tests/test_mcp_server.py; these two pin the predicate itself.
#
# The predicate has two halves and neither looks at the table. First
# ORIGIN: only a name the EXPORT does not know is caller-invented (a real
# appliance object stays a real appliance object, even when it happens to
# be named like a pseudonym). Then SHAPE: does that invented name follow
# the pseudonym pattern. Deliberately not "is it in the table" - that would
# make the refusal depend on the very file it protects, and it would let a
# client read off which pseudonyms had been handed out.
# ---------------------------------------------------------------------------


def test_PSEUDONIEMINVOER_alleen_de_invoer_veroorzaakt_de_botsing(tmp_path):
    """The healthy table plus a caller who asks on with a pseudonym from an
    earlier answer. Without the input the table validates without a
    murmur - so the input is the whole cause, and the message says so
    instead of pointing at the file."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "LB_VS_PORTAAL"}), encoding="utf-8")
    before = path.read_bytes()
    a = Answer(
        question="wat breekt er als object-01 verloopt",
        findings=[Finding(subject="object-01", outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")],
    )
    with pytest.raises(PseudonymAsInput) as err:
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("LB_VS_PORTAAL",),
            caller_name="object-01",
            pseudonym_table_path=path,
        )
    message = str(err.value)
    assert "pseudoniem uit een eerder antwoord" in message
    assert str(path) not in message  # nothing to repair, so no path to point at
    assert "LB_VS_PORTAAL" not in message
    assert path.read_bytes() == before  # a refusal writes nothing


def test_PSEUDONIEMINVOER_een_echt_object_met_pseudoniemvorm_blijft_een_tabelweigering(tmp_path):
    """The other side of the gate: a REAL appliance object that happens to
    carry the pseudonym shape. The export knows this name, so asking about
    it is not "asking on with a pseudonym" - the collision with the table's
    own pseudonym is then a genuine namespace problem and keeps the table
    message, including its repair advice."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "OUDE_NAAM"}), encoding="utf-8")
    a = Answer(
        question="v",
        findings=[Finding(subject="object-01", outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("object-01",),
            caller_name="object-01",
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)
    assert "pseudoniem uit een eerder antwoord" not in str(err.value)


# ---------------------------------------------------------------------------
# The issued certificates: a SECOND collection of real object names next to
# affected_vservers. Anything that can carry a name gets replaced, not only
# what happens to be rendered today.
# ---------------------------------------------------------------------------


def test_the_limited_copy_pseudonymizes_the_issued_certificates(tmp_path):
    """Tweede verzameling met echte objectnamen. `affected_vservers` werd al
    vervangen; een nieuw veld dat dat niet wordt, is een lek zodra iets de
    kopie uitleest - en de discipline in dit bestand is "vervang alles wat
    een naam kan dragen", niet "alleen wat vandaag gerenderd wordt".
    """
    from nsmcp.disclosure import _limit

    answer = ImpactAnswer(
        question="wat breekt er met ca_uitgever",
        findings=[
            Finding(
                subject="ca_uitgever",
                outcome="geeft uit",
                certainty=Certainty.ESTABLISHED,
                evidence="linkcertkeyname naar LEAF_GEHEIM",
            )
        ],
        issued_certificates=("LEAF_GEHEIM",),
    )
    copy = _limit(answer, (), tmp_path / "openheid-vertaaltabel.json")
    assert copy.issued_certificates, "de beperkte kopie verloor het veld met uitgegeven certificaten"
    assert all(n.startswith("object-") for n in copy.issued_certificates)
    assert "LEAF_GEHEIM" not in copy.findings[0].evidence


def test_the_name_collection_reads_the_issued_certificates_field(tmp_path):
    """`getattr`-bewaker: een hernoeming van het veld die deze
    string-opzoeking vergeet, valt stil terug op de fail-closed default en
    laat de naam onvervangen staan. De naam staat hier ALLEEN in het veld en
    in een bewijsregel die de verzameling niet leest, zodat een verouderde
    opzoeking hier luid faalt in plaats van zich achter een subject te
    verstoppen.
    """
    answer = ImpactAnswer(
        question="wat breekt er met ca_uitgever",
        findings=[
            Finding(
                subject="ca_uitgever",
                outcome="geeft uit",
                certainty=Certainty.ESTABLISHED,
                evidence="linkcertkeyname naar LEAF_GEHEIM",
            )
        ],
        issued_certificates=("LEAF_GEHEIM",),
    )
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=(),
        pseudonym_table_path=tmp_path / "openheid-vertaaltabel.json",
    )
    assert "LEAF_GEHEIM" not in text
    assert "object-" in text


def test_INTEGRATION_the_issuing_chain_leaks_no_export_name_in_any_field(tmp_path):
    """De invariant zelf, langs de ECHTE motor: in de stand `beperkt` zendt
    deze server nooit een echte objectnaam uit. De ketenronde bracht twee
    nieuwe plekken waar zo'n naam in VRIJE TEKST terechtkomt - de
    bewijsregel van de uitgiftebevinding (`certkey=`, `linkcertkeyname=`) en
    de herkoppelstap van `certificaat_wat_moet_ik_doen` - en die worden door geen enkel
    apart uitgelezen veld gedekt. Deze test kijkt daarom naar de volledige
    tekst van beide antwoorden, niet naar `issued_certificates` alleen.
    """
    export = _real_export(
        tmp_path,
        certs=[
            {"certkey": "INT_UITGEVER", "daystoexpiration": 40, "status": "Valid"},
            {
                "certkey": "LEAF_DIENST",
                "daystoexpiration": 300,
                "status": "Valid",
                "linkcertkeyname": "INT_UITGEVER",
            },
        ],
        bindings={
            "LB_VS_PORTAAL": [
                {
                    "certkeyname": "LEAF_DIENST",
                    "vservername": "LB_VS_PORTAAL",
                    "snicert": False,
                    "ca": False,
                }
            ]
        },
    )
    knowledge = _real_knowledge()
    impact = what_breaks(export, knowledge, "INT_UITGEVER")
    action = what_to_do(impact, knowledge, "INT_UITGEVER")
    # premise: the names really sit in free text of both answers
    assert any("LEAF_DIENST" in b.evidence for b in impact.findings)
    assert any("LEAF_DIENST" in b.outcome for b in action.findings)

    names = names_from_export(export)
    assert "LEAF_DIENST" in names and "LB_VS_PORTAAL" in names  # premise
    for answer, tool in ((impact, "certificaat_wat_breekt_er"), (action, "certificaat_wat_moet_ik_doen")):
        text = render(
            answer,
            Disclosure.LIMITED,
            tool=tool,
            extra_names=names,
            caller_name="INT_UITGEVER",
            pseudonym_table_path=tmp_path / "tabel.json",
        )
        _no_name_leaks(text, names)
        assert "object-" in text


# ---------------------------------------------------------------------------
# De reparatie die een ONGELEZEN dienst zichtbaar maakt, mag zijn naam niet
# laten lekken.
#
# `names_from_export()` las tot deze ronde twee bronnen: config/sslcertkey
# (veld certkey) en het bindingsbestand (veld vservername). Een virtuele
# server die ALLEEN in de objectbron van de parents staat - precies het
# geval dat het nieuwe leesgat meldt - kwam in geen van beide voor. Zijn
# naam zou dus onvervangen door het filter komen, in de stand die belooft
# dat er geen echte objectnaam uitgaat.
# ---------------------------------------------------------------------------


def _export_with_an_unread_parent(tmp_path: Path, unread: str = "AAA_GEHEIM") -> Path:
    """Een echte export waarin de objectbron TWEE virtuele servers kent en
    het bindingsbestand er maar EEN als parent draagt - de vorm die op de
    echte labexport gemeten is."""
    _real_export(tmp_path)
    m = tmp_path / "export"
    (m / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": "LB_VS_PORTAAL"}, {"vservername": unread}]}),
        encoding="utf-8",
    )
    manifest_path = m / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"]["config/sslvserver"] = {"status": "OK"}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(m)
    return m


def test_INTEGRATION_the_unread_parent_really_reaches_the_answer_text(tmp_path):
    """Premisse-assertie: zonder deze meting bewijst de lektest hieronder
    niets, want dan staat de naam er sowieso niet in."""
    export = load_export(_export_with_an_unread_parent(tmp_path))
    answer = what_breaks(export, _real_knowledge(), _CERT)
    assert "AAA_GEHEIM" in answer.to_text()


def test_INTEGRATION_an_unread_binding_parent_leaks_no_name_in_the_limited_setting(tmp_path):
    export = load_export(_export_with_an_unread_parent(tmp_path))
    answer = what_breaks(export, _real_knowledge(), _CERT)
    names = names_from_export(export) + (_CERT,)
    assert "AAA_GEHEIM" in names, "een virtuele server die alleen de objectbron kent is nog steeds een echte objectnaam"
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)
    assert "object-" in text


# ---------------------------------------------------------------------------
# Lekklasse: een ruwe veldwaarde in een leesgat-reden.
#
# `names_from_export()` leest de velden `certkey` en `vservername`. Een naam
# die in een ANDERE vorm in de export staat (een lijst, een dict) komt daar
# niet in voor en wordt dus niet gepseudonimiseerd - terwijl impact.py hem
# met `waarde {raw!r}` letterlijk in de reden zette. Gemeten op zowel
# `certkeyname` (bestond al) als `linkcertkeyname` (kwam er in de
# ketenronde bij).
# ---------------------------------------------------------------------------


def _leak_export(tmp_path: Path, veld: str, waarde) -> Path:
    """Een echte export waarin `veld` een naam draagt in een vorm die de
    naamverzameling niet leest."""
    if veld == "certkeyname":
        _real_export(tmp_path, bindings={"LB_VS_PORTAAL": [{"certkeyname": waarde, "vservername": "LB_VS_PORTAAL"}]})
    else:
        _real_export(
            tmp_path,
            certs=[
                {"certkey": _CERT, "daystoexpiration": 9, "status": "Valid", "linkcertkeyname": waarde},
            ],
        )
    return tmp_path / "export"


def test_a_raw_certkeyname_value_does_not_reach_the_answer_verbatim(tmp_path):
    export = load_export(_leak_export(tmp_path, "certkeyname", ["VERBORGEN_CA"]))
    answer = what_breaks(export, _real_knowledge(), _CERT)
    tekst = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names_from_export(export) + (_CERT,),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "VERBORGEN_CA" not in tekst, "een ruwe veldwaarde hoort getypeerd te worden, niet gereproduceerd"
    assert "list" in tekst, "de VORM hoort de operator wel te bereiken - die is de diagnose"


def test_a_raw_linkcertkeyname_value_does_not_reach_the_answer_verbatim(tmp_path):
    export = load_export(_leak_export(tmp_path, "linkcertkeyname", ["VERBORGEN_CA"]))
    answer = what_breaks(export, _real_knowledge(), _CERT)
    tekst = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names_from_export(export) + (_CERT,),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "VERBORGEN_CA" not in tekst
    assert "list" in tekst


def test_INTEGRATION_status_cve_controle_limited_leaks_no_export_name(tmp_path):
    """The condition evidence of the CVE verdict names REAL appliance objects
    - the Gateway vservers from `config/vpnvserver`, and for a SAML action or
    LSN group the name straight out of the running config. Those names appear
    in no other name family (they are neither certificates nor ssl-vserver
    bindings), so without `names_in_predicate_sources` in the collection the
    very evidence that makes the condition honest would leak the real name in
    this setting. Measured on the REAL export, where VSRV-003, VSRV-002
    and VSRV-001 really exist.
    """
    from nsmcp.cve import cve_check

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    bulletin = {
        "bulletin": "CTX-DEMO-GW",
        "datum": "2026-08-19",
        "getroffen": {"14.1": "< 72.61"},
        "fix": {"14.1": "72.61"},
        "cves": [
            {"id": "CVE-2026-11111", "cvss": 9.3, "kern": "Gateway overflow", "voorwaarde": "heeft_gateway_vserver"}
        ],
        "advies": "Upgrade naar 14.1-72.61 of hoger.",
        "extraStapNaUpgrade": "",
    }
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(bulletin,))
    answer = cve_check(export, knowledge)
    # Premise: the real name really sits in the answer at full disclosure.
    assert "VSRV-003" in answer.to_text()

    names = names_from_export(export)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names + ("VSRV-003", "VSRV-002", "VSRV-001"))
    assert "object-" in text


def test_INTEGRATION_status_cve_controle_limited_masks_a_name_only_the_condition_knows(tmp_path):
    """The sharper version of the test above. On the live fixture the Gateway
    vservers happen to ALSO be ssl-vservers with a certificate binding, so
    the old name collection knew them by accident. A Gateway without such a
    binding - and a SAML action, which is not an object source at all - is
    known to NO other family, and that is exactly the name the condition
    evidence writes into the answer.
    """
    from nsmcp.cve import cve_check

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    (m / "objects" / "vpnvserver.json").write_text(
        json.dumps({"vpnvserver": [{"name": "GEHEIME_GATEWAY"}]}), encoding="utf-8"
    )
    running = "add authentication samlAction GEHEIME_SAML_ACTIE -samlIdPCertName x\n"
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/nsversion": {"status": "OK"},
                    "config/vpnvserver": {"status": "OK"},
                    "config/nsrunningconfig": {"status": "OK"},
                },
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    export = load_export(m)
    bulletins = (
        {
            "bulletin": "CTX-A",
            "datum": "2026-08-19",
            "getroffen": {"14.1": "< 73.32"},
            "fix": {"14.1": "73.32"},
            "cves": [
                {"id": "CVE-A", "cvss": 9.3, "kern": "Gateway overflow", "voorwaarde": "heeft_gateway_vserver"},
                {"id": "CVE-B", "cvss": 9.8, "kern": "Authentication bypass", "voorwaarde": "heeft_saml_action"},
            ],
            "advies": "Upgrade.",
            "extraStapNaUpgrade": "",
        },
    )
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=bulletins)
    answer = cve_check(export, knowledge)
    full = answer.to_text()
    assert "GEHEIME_GATEWAY" in full and "GEHEIME_SAML_ACTIE" in full  # premise

    names = names_from_export(export)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME_GATEWAY", "GEHEIME_SAML_ACTIE"))


def test_INTEGRATION_status_cve_controle_limited_masks_the_http2_association(tmp_path):
    """regressionb. The HTTP/2 condition names TWO appliance objects in its
    evidence: the profile with http2 on AND the object that hangs it on
    itself. A csvserver that carries nothing but an `httpprofilename` is
    known to no other family here - it has no certificate binding, and the
    dienst family reads lbvservers - so without the reference families in
    `names_in_predicate_sources` the very evidence that makes this condition
    honest would leak both real names in this setting.
    """
    from nsmcp.cve import cve_check

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    (m / "objects" / "nshttpprofile.json").write_text(
        json.dumps({"nshttpprofile": [{"name": "GEHEIM_PROFIEL", "http2": "ENABLED"}]}),
        encoding="utf-8",
    )
    (m / "objects" / "csvserver.json").write_text(
        json.dumps({"csvserver": [{"name": "GEHEIME_CS", "httpprofilename": "GEHEIM_PROFIEL"}]}),
        encoding="utf-8",
    )
    running = "set ns config -IPAddress 10.0.0.1\n"
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/nsversion": {"status": "OK"},
                    "config/nshttpprofile": {"status": "OK"},
                    "config/csvserver": {"status": "OK"},
                    "config/lbvserver": {"status": "EMPTY"},
                    "config/vpnvserver": {"status": "EMPTY"},
                    "config/service": {"status": "EMPTY"},
                    "config/servicegroup": {"status": "EMPTY"},
                    "config/nsrunningconfig": {"status": "OK"},
                },
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    export = load_export(m)
    bulletins = (
        {
            "bulletin": "CTX-B",
            "datum": "2026-08-19",
            "getroffen": {"14.1": "< 73.32"},
            "fix": {"14.1": "73.32"},
            "cves": [{"id": "CVE-C", "cvss": 8.7, "kern": "HTTP/2 DoS", "voorwaarde": "heeft_http2_profiel"}],
            "advies": "Upgrade.",
            "extraStapNaUpgrade": "",
        },
    )
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=bulletins)
    answer = cve_check(export, knowledge)
    full = answer.to_text()
    # Premise: the condition really is established here, and it really names
    # both objects at full disclosure.
    assert "voorwaarde heeft_http2_profiel aanwezig" in full
    assert "GEHEIM_PROFIEL" in full and "GEHEIME_CS" in full

    names = names_from_export(export)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIM_PROFIEL", "GEHEIME_CS"))
    assert "object-" in text


def _dienst_export(tmp_path: Path):
    """A minimal export with one lbvserver, its servicegroup and two
    members - the same shapes `tests/test_dienst.py` uses, built here (not
    imported from there) so this file's own hash/manifest wiring stays the
    single source of truth for what "a real export" means in these
    INTEGRATION tests.
    """
    from nsmcp.export import load_export as _load

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-02T06:00:00.0000000Z",
        "resources": {"config/lbvserver": {"status": "OK"}},
        "files": {},
    }
    (m / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": [{"name": "GEHEIME_DIENST", "effectivestate": "UP", "health": "100"}]}),
        encoding="utf-8",
    )
    # The aggregate shape as the REAL collector writes it (measured on
    # `tests/fixtures/lab-export-vpx-20260826/bindings/vpnvserver_binding
    # .by-parent.json`): `data.<bindingResource>` is an OBJECT carrying the
    # parent key plus the nested binding lists, never a bare list. See
    # `tests/test_dienst.py::test_real_aggregate_files_write_data_resource_as_an_object`.
    for fname, body in (
        (
            "lbvserver_binding.by-parent.json",
            {
                "shape": "aggregate",
                "parents": [
                    {
                        "parentName": "GEHEIME_DIENST",
                        "outcome": "OK",
                        "data": {
                            "lbvserver_binding": {
                                "name": "GEHEIME_DIENST",
                                "lbvserver_servicegroup_binding": [{"servicegroupname": "GEHEIME_GROEP"}],
                            }
                        },
                    }
                ],
            },
        ),
        (
            "servicegroup_binding.by-parent.json",
            {
                "shape": "aggregate",
                "parents": [
                    {
                        "parentName": "GEHEIME_GROEP",
                        "outcome": "OK",
                        "data": {
                            "servicegroup_binding": {
                                "servicegroupname": "GEHEIME_GROEP",
                                "servicegroup_servicegroupmember_binding": [
                                    {"servername": "GEHEIME_WEBSERVER", "port": 443, "svrstate": "UP"},
                                    {"ip": "10.44.55.66", "port": 443, "svrstate": "UP"},
                                ],
                            }
                        },
                    }
                ],
            },
        ),
    ):
        raw = json.dumps(body)
        (m / "bindings" / fname).write_text(raw, encoding="utf-8")
        manifest["files"][f"bindings/{fname}"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    (m / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(m)
    return _load(m)


def test_INTEGRATION_dienst_status_limited_leaks_no_export_name(tmp_path):
    """`dienst_status` puts the lbvserver, its servicegroup and every member
    into `Finding.subject` (dienst.py), so the "second net" in
    `_collect_names()` already stops the real names from leaking - this
    proves that end to end for all three name shapes at once, through a
    REAL `Export` (hash-verified, same wiring as `tests/test_dienst.py`),
    not a hand-built `Answer`.
    """
    from nsmcp.dienst import service_status

    export = _dienst_export(tmp_path)
    knowledge = _real_knowledge()
    answer = service_status(export, knowledge, "GEHEIME_DIENST")
    assert "GEHEIME_WEBSERVER" in answer.to_text()  # premise

    names = names_from_export(export)
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_status",
        extra_names=names,
        caller_name="GEHEIME_DIENST",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME_DIENST", "GEHEIME_GROEP", "GEHEIME_WEBSERVER"))
    assert "object-" in text


def test_INTEGRATION_dienst_status_limited_masks_the_queried_dienst_name(tmp_path):
    """The sharper version of the test above, and the exact measurement
    behind `dienst.names_in_service_sources`.

    `dienst_status` passes its `dienst` argument to `render()` as
    `caller_name`, exactly like `certnaam` in `certificaat_wat_breekt_er`.
    That seam (`render()` in disclosure.py) classifies a name as
    caller-INVENTED whenever `extra_names` does not contain it - and before
    `names_in_service_sources` existed, NO family in `names_from_export()`
    ever read an lbvserver name, so a genuinely known dienst was
    misclassified as invented and rendered as the fixed
    "(onbekende naam uit de vraag)" text instead of a stable pseudonym: not
    a literal leak (the finding-subject collection already replaces the
    text), but a false claim that a known object is unknown. Proven here
    against the SAME export and the SAME name `names_from_export()` must
    now cover.
    """
    from nsmcp.dienst import service_status

    export = _dienst_export(tmp_path)
    knowledge = _real_knowledge()
    answer = service_status(export, knowledge, "GEHEIME_DIENST")

    names = names_from_export(export)
    assert "GEHEIME_DIENST" in names  # premise: the new family covers it

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_status",
        extra_names=names,
        caller_name="GEHEIME_DIENST",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "onbekende naam" not in text
    _no_name_leaks(text, ("GEHEIME_DIENST",))
    assert "object-" in text


# Vijfde naamfamilie: `dienst_status` accepteert ELKE naam die het
# ook kan afdrukken. De eerste versie van `dienst.names_in_service_sources`
# las alleen lbvserver-namen, dus een vraag over een ECHTE servicegroup of een
# ECHT lid werd aan de openheidsnaad nog steeds als verzonnen geclassificeerd.
# Elke test hieronder bewijst eerst de premisse in 'volledig' (deze naam staat
# echt in de tekst die dit product afdrukt) en pas daarna het gedrag in
# 'beperkt'.
def _dienst_premise_and_limited(tmp_path, asked: str) -> str:
    """FULL first (the premise: this product really prints this name), then
    LIMITED with that same name as the caller argument."""
    from nsmcp.dienst import service_status

    export = _dienst_export(tmp_path)
    knowledge = _real_knowledge()
    full = render(service_status(export, knowledge, "GEHEIME_DIENST"), Disclosure.FULL, tool="dienst_status")
    assert asked in full, f"premisse ontbreekt: {asked!r} staat niet in de volledige tekst: {full}"

    names = names_from_export(export)
    assert asked in names, f"de naamfamilie kent {asked!r} niet"
    return render(
        service_status(export, knowledge, asked),
        Disclosure.LIMITED,
        tool="dienst_status",
        extra_names=names,
        caller_name=asked,
        pseudonym_table_path=tmp_path / "tabel.json",
    )


def test_INTEGRATION_dienst_status_limited_masks_a_servicegroup_name_from_the_question(tmp_path):
    text = _dienst_premise_and_limited(tmp_path, "GEHEIME_GROEP")
    assert "onbekende naam" not in text
    _no_name_leaks(text, ("GEHEIME_GROEP",))
    assert "object-" in text


def test_INTEGRATION_dienst_status_limited_masks_a_member_name_from_the_question(tmp_path):
    text = _dienst_premise_and_limited(tmp_path, "GEHEIME_WEBSERVER")
    assert "onbekende naam" not in text
    _no_name_leaks(text, ("GEHEIME_WEBSERVER",))
    assert "object-" in text


def test_INTEGRATION_dienst_status_limited_masks_a_member_ip_from_the_question(tmp_path):
    """A member bound by IP carries no servername; the IP itself is what this
    product prints and what a caller can therefore ask about."""
    text = _dienst_premise_and_limited(tmp_path, "10.44.55.66")
    assert "onbekende naam" not in text
    _no_name_leaks(text, ("10.44.55.66",))
    assert "object-" in text


def test_INTEGRATION_status_overzicht_limited_leaks_no_export_name(tmp_path):
    """`overview()` writes the HA node name straight into the "HA" finding's
    evidence (config/hanode). Measured on the REAL export, where
    host-006.lab.example is the real HA node - and, unlike the certkey/vserver
    families, that name is neither a certificate nor an sslvserver binding,
    so it sat in none of the five families that predate
    `overzicht.names_in_overview_sources` (it leaked verbatim
    in 'beperkt' before that sixth family was added).
    """
    from nsmcp.overzicht import overview

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    knowledge = _real_knowledge()
    answer = overview(export, knowledge)
    # Premise: the real HA node name really sits in the FULL-disclosure text -
    # asserted on exactly that text (`render(..., Disclosure.FULL, ...)`, as
    # in the dienst case above), not on `answer.to_text()`, so the claim and
    # the measurement are the same thing.
    assert "host-006.lab.example" in render(answer, Disclosure.FULL, tool="status_overzicht")

    names = names_from_export(export)
    assert "host-006.lab.example" in names  # the sixth family covers it

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_overzicht",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names + ("host-006.lab.example",))
    assert "object-" in text
    # Label collision, MEASURED: `_collect_names` puts every finding SUBJECT
    # in the replacement set, and the replacement is a plain substring pass.
    # A family label that is a substring of another label - or of the
    # not-assessed subject - therefore mutilates that other line ("GSLB-
    # vservers" came out as "GSobject-07" while "LB-vservers" was a
    # finding subject). The labels are now chosen so no label sits inside
    # another; this assertion is the guard that keeps it that way.
    assert "GSobject" not in text
    assert "GSLB-vservers" in text


def test_INTEGRATION_limited_keeps_this_products_own_labels_readable(tmp_path):
    """`_collect_names` used to take EVERY finding subject as an appliance
    object name. In 'beperkt' that turned this product's OWN vocabulary into
    pseudonyms - `build`, `HA`, the four vserver family labels, `CVE-oordeel`
    - and the public bulletin and CVE identifiers with them; and it wrote all
    of those into the operator's translation table as if they were real
    objects on their appliance. They are not: masking them costs the reader
    the answer and pollutes the one file that decodes the real names.

    Measured on the REAL export, with the real object names asserted absent
    in the same texts - the masking that DOES belong here is untouched.
    """
    from nsmcp.cve import cve_check
    from nsmcp.overzicht import overview

    export = load_export(Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826")
    table = tmp_path / "tabel.json"
    names = names_from_export(export)

    overview_text = render(
        overview(export, _real_knowledge()),
        Disclosure.LIMITED,
        tool="status_overzicht",
        extra_names=names,
        pseudonym_table_path=table,
    )
    for label in (
        "build:",
        "HA:",
        "Loadbalancing-vservers",
        "Contentswitching-vservers",
        "Gateway-vservers",
        "AAA-vservers",
        "GSLB-vservers",
    ):
        assert label in overview_text, f"eigen label {label!r} gemaskeerd:\n{overview_text}"
    _no_name_leaks(overview_text, names + ("host-006.lab.example",))

    bulletin = {
        "bulletin": "CTX-DEMO-GW",
        "datum": "2026-08-19",
        "getroffen": {"14.1": "< 72.61"},
        "fix": {"14.1": "72.61"},
        "cves": [
            {"id": "CVE-2026-11111", "cvss": 9.3, "kern": "Gateway overflow", "voorwaarde": "heeft_gateway_vserver"}
        ],
        "advies": "Upgrade naar 14.1-72.61 of hoger.",
        "extraStapNaUpgrade": "",
    }
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(bulletin,))
    cve_text = render(
        cve_check(export, knowledge),
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names,
        pseudonym_table_path=table,
    )
    for label in ("CVE-oordeel", "CVE-2026-11111", "CTX-DEMO-GW"):
        assert label in cve_text, f"eigen label {label!r} gemaskeerd:\n{cve_text}"
    _no_name_leaks(cve_text, names + ("VSRV-003", "VSRV-002", "VSRV-001"))

    stored = set(json.loads(table.read_text(encoding="utf-8")).values())
    for forbidden in (
        "build",
        "HA",
        "CVE-oordeel",
        "CVE-2026-11111",
        "CTX-DEMO-GW",
        "Loadbalancing-vservers",
        "Contentswitching-vservers",
        "Gateway-vservers",
        "AAA-vservers",
    ):
        assert forbidden not in stored, f"{forbidden!r} staat als 'echte naam' in de pseudoniemtabel van de operator"


def test_a_dienst_answer_still_has_its_subjects_masked(tmp_path):
    """Counter-probe for the flag above: `dienst.py` subjects ARE object
    names (the service, the servicegroup, the members), so a blanket 'never
    mask a subject' would be a leak. This test fails the moment that flag is
    set there too."""
    text = _dienst_premise_and_limited(tmp_path, "GEHEIME_DIENST")
    assert "object-" in text
    _no_name_leaks(text, ("GEHEIME_DIENST",))


# ---------------------------------------------------------------------------
# regression. The candidate names of `certificaat_wat_breekt_er` /
# `certificaat_wat_moet_ik_doen` are REAL certificate names off the appliance.
# They arrive in the answer through a route that did not exist before (the
# outcome of the candidate finding, and - via `what_to_do` - an answer built
# by another module altogether), so this measures on the REAL export that
# 'volledig' shows them and 'beperkt' does not.
# ---------------------------------------------------------------------------

_LIVE_FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


def test_INTEGRATION_certificate_candidates_are_real_names_in_volledig():
    """Premise for the two tests below: with a half name the answer really
    does carry the certificate names of this export. Measured on the real
    collector export (2026-09-03): its four certkeys are
    ns-sftrust-certificate, ns-server-certificate, CERT-004 and
    CERT-009, two of which carry 'ns-s'."""
    export = load_export(_LIVE_FIXTURE)
    knowledge = _real_knowledge()
    text = render(what_breaks(export, knowledge, "ns-s"), Disclosure.FULL, tool="certificaat_wat_breekt_er")
    assert (
        "kandidaten (naam bevat 'ns-s', hoofdletterongevoelig): ns-server-certificate, ns-sftrust-certificate"
    ) in text


def test_INTEGRATION_certificate_candidates_do_not_exist_in_beperkt(tmp_path):
    """RE-PINNED IN regression. This test used to
    demand that the candidate line came out here AS PSEUDONYMS. That was the
    defect: stable pseudonyms plus a ladder of probes (a, ab, abc ...) turn
    the line into an adaptive substring oracle, so a client reconstructs a
    real certificate name it was never shown. Naming candidates is a
    'volledig' behaviour; below it the line is gone entirely - names, count
    and all. See `Finding.only_in_full` and `disclosure._without_full_only`.
    """
    export = load_export(_LIVE_FIXTURE)
    knowledge = _real_knowledge()
    names = names_from_export(export)
    # Premise: the family that has to cover these names really knows them.
    assert "ns-server-certificate" in names and "ns-sftrust-certificate" in names
    # Premise: at 'volledig' the candidates line is still there.
    assert "- kandidaten" in render(
        what_breaks(export, knowledge, "ns-s"),
        Disclosure.FULL,
        tool="certificaat_wat_breekt_er",
    )

    text = render(
        what_breaks(export, knowledge, "ns-s"),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names,
        caller_name="ns-s",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)
    assert "kandidaten" not in text, text


def test_INTEGRATION_certificate_candidates_of_the_advice_tool_are_pseudonyms_too(tmp_path):
    """`what_to_do` builds its OWN answer - a bare Answer, without the
    ImpactAnswer collections - so the candidate names travel there through a
    different route and need their own measurement."""
    export = load_export(_LIVE_FIXTURE)
    knowledge = _real_knowledge()
    names = names_from_export(export)
    answer = what_to_do(what_breaks(export, knowledge, "ns-s"), knowledge, "ns-s")
    # Premise: without masking the real names really are in this text.
    assert "ns-sftrust-certificate" in render(answer, Disclosure.FULL, tool="certificaat_wat_moet_ik_doen")

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_moet_ik_doen",
        extra_names=names,
        caller_name="ns-s",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, names)
    # RE-PINNED IN regression, for the same reason as the test above: the
    # advice tool takes the same half name through its own route, so the
    # oracle had to be closed on that route too.
    assert "kandidaten" not in text, text


def test_INTEGRATION_the_candidate_subject_never_reaches_the_pseudonym_table(tmp_path):
    """The subject of the candidate line is this product's own vocabulary
    plus the term the CALLER typed. Collecting it as an object name would
    write caller input into the operator's translation table - the one file
    that decodes the real names. `Finding.subject_is_name=False` keeps it
    out.

    SINCE regression the line does not reach a 'beperkt' rendering at all
    (`only_in_full`), so the table stays clean for a second reason as well.
    The flag itself is therefore asserted directly below: without that, this
    test would silently stop measuring what its name promises the moment the
    line came back at any level."""
    export = load_export(_LIVE_FIXTURE)
    table = tmp_path / "tabel.json"
    render(
        what_breaks(export, _real_knowledge(), "ns-s"),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names_from_export(export),
        caller_name="ns-s",
        pseudonym_table_path=table,
    )
    stored = set(json.loads(table.read_text(encoding="utf-8")).values())
    for forbidden in stored:
        assert "kandidaten" not in forbidden, f"{forbidden!r} staat als 'echte naam' in de tabel"
    assert "ns-s" not in stored
    assert candidate_finding("ns-s", ("x",), 1).subject_is_name is False


def test_INTEGRATION_candidates_are_masked_even_without_the_structural_collection(tmp_path):
    """The SECOND net, the same reason `affected_vservers` and
    `issued_certificates` are read out of the answer itself: should
    `extra_names` ever be empty (a caller not following the structure), this
    product must not fall straight back to zero protection.

    MEASURED before this repair (2026-09-03, real export, extra_names=()):
    the candidate line came out as "...erver-certificate,
    ...ftrust-certificate" - the caller term replaced, the REST of two real
    certificate names left standing.

    SINCE regression there is a net BEFORE this one - the line is dropped below
    'volledig' altogether - and this test keeps standing behind it: should
    that drop ever be undone, masking must still hold here.
    """
    export = load_export(_LIVE_FIXTURE)
    text = render(
        what_breaks(export, _real_knowledge(), "ns-s"),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=(),
        caller_name="ns-s",
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("ns-server-certificate", "ns-sftrust-certificate"))
    for tail in ("erver-certificate", "ftrust-certificate"):
        assert tail not in text, f"halve echte naam lekt: {tail}\n---\n{text}"


def test_INTEGRATION_status_cve_controle_limited_masks_an_uncorrelated_cs_vserver(tmp_path):
    """regression. The DoH condition on a CS vserver writes a name into the
    evidence that no other family here knows: a `set cs vserver <naam>
    -dnsOverHttps ENABLED` line WITHOUT a matching object or `add` line. That
    line is read and set aside, and saying so names the vserver - so without
    the correlated line source in `names_in_predicate_sources` the very
    sentence that makes the answer honest would leak the real name in this
    setting.

    regression: that sentence is now a READ GAP ("niet te correleren") rather
    than an established absence, and it travels into the "NIET VASTGESTELD"
    block as well as into the evidence - so the masking has to hold in both
    places, which is exactly what this test asks.
    """
    from nsmcp.cve import cve_check

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    (m / "objects" / "csvserver.json").write_text(json.dumps({"errorcode": 0, "message": "Done"}), encoding="utf-8")
    (m / "objects" / "lbvserver.json").write_text(json.dumps({"errorcode": 0, "message": "Done"}), encoding="utf-8")
    running = "set cs vserver GEHEIME_CS_DOH -dnsOverHttps ENABLED\n"
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/nsversion": {"status": "OK"},
                    "config/csvserver": {"status": "EMPTY"},
                    "config/lbvserver": {"status": "EMPTY"},
                    "config/nsrunningconfig": {"status": "OK"},
                },
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    export = load_export(m)
    bulletin = {
        "bulletin": "CTX-DEMO-DOH",
        "datum": "2026-06-30",
        "getroffen": {"14.1": "< 72.61"},
        "fix": {"14.1": "72.61"},
        "cves": [
            {"id": "CVE-2026-8655", "cvss": 8.8, "kern": "DoS; DNS-proxy", "voorwaarde": "heeft_lb_oracle_of_dns"}
        ],
        "advies": "Upgrade naar 14.1-72.61 of hoger.",
        "extraStapNaUpgrade": "",
    }
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(bulletin,))
    answer = cve_check(export, knowledge)
    # Premise: at full disclosure the dismissal really names the vserver.
    volledig = answer.to_text()
    assert "GEHEIME_CS_DOH" in volledig and "niet te correleren" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME_CS_DOH",))
    assert "object-" in text


def test_INTEGRATION_status_cve_controle_limited_masks_a_contradicted_vserver(tmp_path):
    """regression. The source contradiction writes a name into the evidence that
    exists in this export on ONE line only: `config/lbvserver` was read and
    returned nothing, while the running config ADDS a DNS vserver. The
    sentence that makes that honest ("brontegenspraak: ... object <naam> ...")
    names the vserver, so without the line source in
    `names_in_predicate_sources` this repair would leak the real name
    in this setting - exactly the way the uncorrelated `set` line did.
    """
    from nsmcp.cve import cve_check

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    (m / "objects" / "csvserver.json").write_text(json.dumps({"errorcode": 0, "message": "Done"}), encoding="utf-8")
    (m / "objects" / "lbvserver.json").write_text(json.dumps({"errorcode": 0, "message": "Done"}), encoding="utf-8")
    running = "add lb vserver GEHEIME_LB_DNS DNS 10.0.0.9 53\n"
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/nsversion": {"status": "OK"},
                    "config/csvserver": {"status": "EMPTY"},
                    "config/lbvserver": {"status": "EMPTY"},
                    "config/nsrunningconfig": {"status": "OK"},
                },
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    export = load_export(m)
    bulletin = {
        "bulletin": "CTX-DEMO-DOH",
        "datum": "2026-06-30",
        "getroffen": {"14.1": "< 72.61"},
        "fix": {"14.1": "72.61"},
        "cves": [
            {"id": "CVE-2026-8655", "cvss": 8.8, "kern": "DoS; DNS-proxy", "voorwaarde": "heeft_lb_oracle_of_dns"}
        ],
        "advies": "Upgrade naar 14.1-72.61 of hoger.",
        "extraStapNaUpgrade": "",
    }
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(bulletin,))
    answer = cve_check(export, knowledge)
    # Premise: at full disclosure the contradiction really names the vserver.
    volledig = answer.to_text()
    assert "GEHEIME_LB_DNS" in volledig and "brontegenspraak" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME_LB_DNS",))
    assert "object-" in text


def test_INTEGRATION_status_cve_controle_limited_masks_a_contradicted_type_and_profile(tmp_path):
    """regression. The two repairs each write a NEW name into
    the evidence: the vserver whose SERVICE TYPE the two halves of the export
    disagree about, and the HTTP profile they disagree about.
    Both sentences are the reason the answer is honest, and both would be the
    reason a real name travelled unmasked if the harvest did not know them -
    so the seam is measured here, on a real `cve_check` answer, and not
    assumed from the fact that a neighbouring name family happens to cover
    them."""
    from nsmcp.cve import cve_check

    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    # The readback says HTTP and http2 ON; the running config says SSL and
    # http2 OFF. Two halves of one export, disagreeing about both.
    (m / "objects" / "lbvserver.json").write_text(
        json.dumps(
            {
                "errorcode": 0,
                "message": "Done",
                "lbvserver": [
                    {
                        "name": "GEHEIM_LB_TYPE",
                        "servicetype": "HTTP",
                        "dnsoverhttps": "ENABLED",
                        "httpprofilename": "GEHEIM_PROFIEL",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (m / "objects" / "nshttpprofile.json").write_text(
        json.dumps(
            {
                "errorcode": 0,
                "message": "Done",
                "nshttpprofile": [
                    {"name": "GEHEIM_PROFIEL", "http2": "ENABLED"},
                ],
            }
        ),
        encoding="utf-8",
    )
    for leeg in ("csvserver", "vpnvserver", "service", "servicegroup"):
        (m / "objects" / f"{leeg}.json").write_text(json.dumps({"errorcode": 0, "message": "Done"}), encoding="utf-8")
    running = (
        "add lb vserver GEHEIM_LB_TYPE SSL 10.0.0.10 443 -dnsOverHttps ENABLED\n"
        "set ns httpProfile GEHEIM_PROFIEL -http2 DISABLED\n"
    )
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    resources = {
        "config/nsversion": {"status": "OK"},
        "config/lbvserver": {"status": "OK"},
        "config/nshttpprofile": {"status": "OK"},
        "config/nsrunningconfig": {"status": "OK"},
    }
    for leeg in ("csvserver", "vpnvserver", "service", "servicegroup"):
        resources[f"config/{leeg}"] = {"status": "EMPTY"}
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": resources,
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    export = load_export(m)
    bulletin = {
        "bulletin": "CTX-DEMO-TEGENSPRAAK",
        "datum": "2026-06-30",
        "getroffen": {"14.1": "< 72.61"},
        "fix": {"14.1": "72.61"},
        "cves": [
            {"id": "CVE-2026-8655", "cvss": 8.8, "kern": "DoS; DNS-proxy", "voorwaarde": "heeft_lb_oracle_of_dns"},
            {"id": "CVE-2026-13474", "cvss": 7.5, "kern": "DoS; HTTP/2", "voorwaarde": "heeft_http2_profiel"},
        ],
        "advies": "Upgrade naar 14.1-72.61 of hoger.",
        "extraStapNaUpgrade": "",
    }
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(bulletin,))
    answer = cve_check(export, knowledge)
    # Premise: at full disclosure both contradictions really name their object.
    volledig = answer.to_text()
    assert volledig.count("brontegenspraak") >= 2, volledig
    assert "GEHEIM_LB_TYPE" in volledig and "GEHEIM_PROFIEL" in volledig
    assert "NIET VASTGESTELD" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIM_LB_TYPE", "GEHEIM_PROFIEL"))
    assert "object-" in text


# ---------------------------------------------------------------------------
# regression. THE TWO SOURCES THE REFERENCE RULE GAINED, AND THE SEAM.
#
# The global default profile and the referring field are reconciled with the
# running config now, and both write SENTENCES that name appliance objects
# the readback alone does not carry: the profile a `set ns param
# -httpProfileName ...` points at, and the profile a `set lb vserver X
# -httpProfileName ...` hangs on a vserver. In the 'beperkt' setting only
# names the collection KNOWS are pseudonymized, so a name the harvest misses
# travels through verbatim - which is why this is measured on a real
# `cve_check` answer instead of assumed from the neighbouring name families.
# ---------------------------------------------------------------------------


def _tegenspraak_export(tmp_path: Path, objects: dict, running: str, resources: dict) -> Path:
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "parsed").mkdir()
    (m / "objects" / "nsversion.json").write_text(
        json.dumps({"nsversion": {"version": "NetScaler NS14.1: Build 72.57.nc"}}), encoding="utf-8"
    )
    for name, payload in objects.items():
        (m / "objects" / f"{name}.json").write_text(
            json.dumps({"errorcode": 0, "message": "Done", **({name: payload} if payload else {})}),
            encoding="utf-8",
        )
    (m / "parsed" / "runningconfig.txt").write_bytes(running.encode("utf-8"))
    alles = {"config/nsversion": {"status": "OK"}, "config/nsrunningconfig": {"status": "OK"}}
    alles.update(resources)
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": alles,
                "files": {"parsed/runningconfig.txt": hashlib.sha256(running.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)
    return m


_HTTP2_BULLETIN = {
    "bulletin": "CTX-DEMO-VERWIJZING",
    "datum": "2026-06-30",
    "getroffen": {"14.1": "< 72.61"},
    "fix": {"14.1": "72.61"},
    "cves": [
        {"id": "CVE-2026-13474", "cvss": 7.5, "kern": "DoS; HTTP/2", "voorwaarde": "heeft_http2_profiel"},
    ],
    "advies": "Upgrade naar 14.1-72.61 of hoger.",
    "extraStapNaUpgrade": "",
}


def test_INTEGRATION_the_global_default_contradiction_masks_the_line_profile(tmp_path):
    """`config/nsparam` names one profile and `set ns param -httpProfileName`
    another. The contradiction sentence prints BOTH - and the one on the line
    exists in this export NOWHERE else: not in the profile readback, not in
    any other name family. Without the running-config half of the harvest it
    travels unmasked through the very sentence that makes the answer honest."""
    from nsmcp.cve import cve_check

    m = _tegenspraak_export(
        tmp_path,
        {
            "nshttpprofile": [{"name": "GEHEIM_UIT", "http2": "DISABLED"}],
            "nsparam": {"httpprofilename": "GEHEIM_UIT"},
            "lbvserver": [{"name": "GEHEIM_VSERVER", "servicetype": "SSL"}],
            "csvserver": [],
            "vpnvserver": [],
            "service": [],
            "servicegroup": [],
        },
        "set ns param -httpProfileName GEHEIM_LIJNPROFIEL\n",
        {
            "config/nshttpprofile": {"status": "OK"},
            "config/nsparam": {"status": "OK"},
            "config/lbvserver": {"status": "OK"},
            "config/csvserver": {"status": "EMPTY"},
            "config/vpnvserver": {"status": "EMPTY"},
            "config/service": {"status": "EMPTY"},
            "config/servicegroup": {"status": "EMPTY"},
        },
    )
    seal_manifest(m)
    export = load_export(m)
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_HTTP2_BULLETIN,))
    answer = cve_check(export, knowledge)
    volledig = answer.to_text()
    # Premise: at full disclosure the sentence really names both halves, and
    # the line half really is absent from every readback family.
    assert "brontegenspraak" in volledig, volledig
    assert "GEHEIM_UIT" in volledig and "GEHEIM_LIJNPROFIEL" in volledig
    assert "NIET VASTGESTELD" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIM_LIJNPROFIEL", "GEHEIM_UIT", "GEHEIM_VSERVER"))
    assert "object-" in text


def test_INTEGRATION_a_binding_set_in_the_running_config_is_masked(tmp_path):
    """The other new source: the line that hangs a profile on a vserver. The
    profile it names is in no readback family either, and it reaches the
    answer through the association sentence."""
    from nsmcp.cve import cve_check

    m = _tegenspraak_export(
        tmp_path,
        {
            "nshttpprofile": [{"name": "GEHEIM_AAN", "http2": "ENABLED"}],
            "lbvserver": [{"name": "GEHEIM_VSERVER", "servicetype": "SSL"}],
            "csvserver": [],
            "vpnvserver": [],
            "service": [],
            "servicegroup": [],
        },
        "add lb vserver GEHEIM_VSERVER SSL 10.0.0.10 443\n"
        "set lb vserver GEHEIM_VSERVER -httpProfileName GEHEIM_LIJNPROFIEL\n",
        {
            "config/nshttpprofile": {"status": "OK"},
            "config/lbvserver": {"status": "OK"},
            "config/csvserver": {"status": "EMPTY"},
            "config/vpnvserver": {"status": "EMPTY"},
            "config/service": {"status": "EMPTY"},
            "config/servicegroup": {"status": "EMPTY"},
        },
    )
    seal_manifest(m)
    export = load_export(m)
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_HTTP2_BULLETIN,))
    answer = cve_check(export, knowledge)
    volledig = answer.to_text()
    assert "verwijst naar profiel GEHEIM_LIJNPROFIEL" in volledig, volledig
    assert "NIET VASTGESTELD" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIM_LIJNPROFIEL", "GEHEIM_AAN", "GEHEIM_VSERVER"))
    assert "object-" in text


def test_INTEGRATION_a_referrer_only_the_running_config_knows_is_masked(tmp_path):
    """And the existence contradiction on a referrer family: `config/service`
    was READ and says there are none, while the running config adds one. The
    sentence names that service, and this export knows it only from that
    line."""
    from nsmcp.cve import cve_check

    m = _tegenspraak_export(
        tmp_path,
        {
            "nshttpprofile": [{"name": "GEHEIM_AAN", "http2": "ENABLED"}],
            "lbvserver": [{"name": "GEHEIM_VSERVER", "servicetype": "SSL", "httpprofilename": "GEHEIM_AAN"}],
            "csvserver": [],
            "vpnvserver": [],
            "service": [],
            "servicegroup": [],
        },
        "add service GEHEIM_DIENST 10.0.0.5 HTTP 80\n",
        {
            "config/nshttpprofile": {"status": "OK"},
            "config/lbvserver": {"status": "OK"},
            "config/csvserver": {"status": "EMPTY"},
            "config/vpnvserver": {"status": "EMPTY"},
            "config/service": {"status": "EMPTY"},
            "config/servicegroup": {"status": "EMPTY"},
        },
    )
    seal_manifest(m)
    export = load_export(m)
    knowledge = Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_HTTP2_BULLETIN,))
    answer = cve_check(export, knowledge)
    volledig = answer.to_text()
    assert "brontegenspraak" in volledig and "GEHEIM_DIENST" in volledig, volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIM_DIENST", "GEHEIM_AAN", "GEHEIM_VSERVER"))
    assert "object-" in text


# ---------------------------------------------------------------------------
# regression. THE SENTENCES THESE REPAIRS ADDED, AND THE SEAM.
#
# Two of them name an appliance object that exists in this export ONLY on a
# running-config line: the service whose name carries a SPACE (and therefore
# stands between double quotes on that line), and the AAA vserver whose family
# is reconciled from now on. In the 'beperkt' setting only names the harvest
# KNOWS are pseudonymized, so both are measured on a real `cve_check` answer.
# ---------------------------------------------------------------------------


_LSN_BULLETIN = {
    "bulletin": "CTX-DEMO-LSN",
    "datum": "2026-06-30",
    "getroffen": {"14.1": "< 72.61"},
    "fix": {"14.1": "72.61"},
    "cves": [
        {"id": "CVE-2026-19489", "cvss": 8.8, "kern": "Memory overflow; SIP ALG", "voorwaarde": "heeft_lsn_sip_alg"},
    ],
    "advies": "Upgrade naar 14.1-72.61 of hoger.",
    "extraStapNaUpgrade": "",
}


def test_INTEGRATION_a_quoted_name_with_a_space_is_masked(tmp_path):
    """A NetScaler name with a space stands between double quotes, and the
    tokenisation reads it WHOLE now. That is a real object name reaching two
    kinds of sentence - the existence contradiction of a referrer family and
    the evidence of a line rule - and a name the harvest does not know travels
    through the 'beperkt' seam verbatim."""
    from nsmcp.cve import cve_check

    dienst = _tegenspraak_export(
        tmp_path / "dienst",
        {
            "nshttpprofile": [{"name": "GEHEIM_AAN", "http2": "ENABLED"}],
            "lbvserver": [{"name": "GEHEIM_VSERVER", "servicetype": "SSL", "httpprofilename": "GEHEIM_AAN"}],
            "csvserver": [],
            "vpnvserver": [],
            "service": [],
            "servicegroup": [],
        },
        'add service "GEHEIME DIENST" 10.0.0.5 HTTP 80\n',
        {
            "config/nshttpprofile": {"status": "OK"},
            "config/lbvserver": {"status": "OK"},
            "config/csvserver": {"status": "EMPTY"},
            "config/vpnvserver": {"status": "EMPTY"},
            "config/service": {"status": "EMPTY"},
            "config/servicegroup": {"status": "EMPTY"},
        },
    )
    export = load_export(dienst)
    answer = cve_check(
        export, Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_HTTP2_BULLETIN,))
    )
    volledig = answer.to_text()
    # Premise: the sentence really names the object, and it names it WHOLE.
    assert "brontegenspraak" in volledig and "GEHEIME DIENST" in volledig, volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-a.json",
    )
    _no_name_leaks(text, ("GEHEIME DIENST", "GEHEIM_AAN", "GEHEIM_VSERVER"))
    assert "object-" in text

    groep = _tegenspraak_export(
        tmp_path / "groep",
        {},
        'add lsn group "GEHEIME GROEP" -sipalg ENABLED\n',
        {},
    )
    export = load_export(groep)
    answer = cve_check(
        export, Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_LSN_BULLETIN,))
    )
    volledig = answer.to_text()
    assert "GEHEIME GROEP" in volledig, volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-b.json",
    )
    _no_name_leaks(text, ("GEHEIME GROEP",))
    assert "object-" in text


_AAA_BULLETIN = {
    "bulletin": "CTX-DEMO-AAA",
    "datum": "2026-06-30",
    "getroffen": {"14.1": "< 72.61"},
    "fix": {"14.1": "72.61"},
    "cves": [
        {"id": "CVE-2026-8452", "cvss": 9.2, "kern": "Memory overread; AAA", "voorwaarde": "heeft_aaa_vserver"},
    ],
    "advies": "Upgrade naar 14.1-72.61 of hoger.",
    "extraStapNaUpgrade": "",
}


def test_INTEGRATION_the_AAA_existence_contradiction_is_masked(tmp_path):
    """The AAA vserver family is reconciled from now on, exactly like the
    Gateway half of the same bulletin sentence. Its existence contradiction
    names a vserver this export knows ONLY from the running config: the
    readback was read and says there is none."""
    from nsmcp.cve import cve_check

    m = _tegenspraak_export(
        tmp_path,
        {"authenticationvserver": []},
        "add authentication vserver GEHEIME_AAA SSL 0.0.0.0\n",
        {"config/authenticationvserver": {"status": "EMPTY"}},
    )
    seal_manifest(m)
    export = load_export(m)
    answer = cve_check(
        export, Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_AAA_BULLETIN,))
    )
    volledig = answer.to_text()
    assert "brontegenspraak" in volledig and "GEHEIME_AAA" in volledig, volledig
    assert "NIET VASTGESTELD" in volledig

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME_AAA",))
    assert "object-" in text


# ---------------------------------------------------------------------------
# regression. The sentence about a line this product could NOT parse.
# ---------------------------------------------------------------------------

_REGEL_ONLEESBAAR_REDEN = "regel(s) in de running config waren niet te ontleden (onafgesloten aanhalingsteken)"


def test_INTEGRATION_the_unreadable_line_sentence_carries_no_name(tmp_path):
    """The new sentence is everything an answer says about a line this product
    could not tokenise - and the very reason it could not is that it does not
    know WHICH object that line names. So the sentence names none: it counts.

    Measured on the real path, on an export whose unreadable line carries a
    name that exists nowhere else in it, and in BOTH settings: the full answer
    may not reproduce the fragment either, so the 'beperkt' seam has nothing
    left to leak."""
    from nsmcp.cve import cve_check

    m = _tegenspraak_export(
        tmp_path,
        {"authenticationvserver": []},
        'add authentication vserver "GEHEIME AAA SSL 0.0.0.0\n',
        {"config/authenticationvserver": {"status": "EMPTY"}},
    )
    seal_manifest(m)
    export = load_export(m)
    answer = cve_check(
        export, Knowledge(version="test", date="2026-08-16", age_days=1, missing=False, cve=(_AAA_BULLETIN,))
    )
    volledig = answer.to_text()
    # Premise: the sentence really is in the answer, and the verdict really
    # rests on it.
    assert f"1 {_REGEL_ONLEESBAAR_REDEN}" in volledig, volledig
    assert "NIET VASTGESTELD" in volledig, volledig
    _no_name_leaks(volledig, ("GEHEIME", "AAA SSL"))

    text = render(
        answer,
        Disclosure.LIMITED,
        tool="status_cve_controle",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    _no_name_leaks(text, ("GEHEIME", "AAA SSL"))


# --------------------------------------------------------------------------
# resolve_pseudonym: the INVERSE of what render() does, for exactly one
# caller - the writing path. At 'beperkt' a caller only ever saw
# pseudonyms, and validate() judges real object names.
# --------------------------------------------------------------------------


def test_resolve_pseudonym_returns_the_real_name(tmp_path):
    from nsmcp.disclosure import resolve_pseudonym

    tabel = tmp_path / "tabel.json"
    render(
        Answer(
            question="x",
            findings=[
                Finding(
                    subject="echte-naam",
                    outcome="iets",
                    certainty=Certainty.ESTABLISHED,
                    evidence="bron",
                )
            ],
        ),
        Disclosure.LIMITED,
        tool="t",
        extra_names=("echte-naam",),
        pseudonym_table_path=tabel,
    )
    pseudoniem = next(iter(json.loads(tabel.read_text(encoding="utf-8"))))
    assert resolve_pseudonym(pseudoniem, ("echte-naam",), tabel) == "echte-naam"
    assert resolve_pseudonym("object-999", ("echte-naam",), tabel) is None
    assert resolve_pseudonym("echte-naam", ("echte-naam",), tabel) == "echte-naam"


def test_minimal_action_needed_not_establishable_with_read_gap(tmp_path):
    """A hash mismatch on the binding file yields a read gap and ZERO
    findings. The old text ('actie nodig: nee') was a false verdict: no
    finding hung on the answer, but that was because the READ failed, not
    because there was nothing to do."""
    export = _real_export(tmp_path, hash_matches=False)
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    assert answer.findings == [] and answer.read_gaps  # premise

    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    # The same honest conclusion, in the shared wording that also holds
    # for a NOT_ESTABLISHED finding without a read gap (see the tests
    # below).
    assert "actie nodig: niet vast te stellen uit dit antwoord" in text


def test_minimal_expired_certificate_stays_visible_next_to_other_terms(tmp_path):
    """The old 'if dagen: ... elif al_verlopen: ...' let an ALREADY EXPIRED
    certificate silently vanish as soon as another certificate with
    remaining days sat in the same findings list."""
    export = _real_export(
        tmp_path,
        certs=[
            {"certkey": "cert_verlopen", "daystoexpiration": -5, "status": "Expired"},
            {"certkey": "cert_ok", "daystoexpiration": 200, "status": "Valid"},
        ],
    )
    knowledge = _real_knowledge()
    answer = what_expires(export, knowledge, 365)

    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_verloopt_er")
    assert "er is al iets verlopen" in text
    assert "200 dagen" in text  # the rest stays visible too, not hidden


def test_broken_pseudonym_table_is_never_overwritten(tmp_path):
    path = tmp_path / "tabel.json"
    path.write_text('{"LB_VS_PORTAAL": "object-01"', encoding="utf-8")  # truncated, no closing brace
    original = path.read_text(encoding="utf-8")

    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )

    assert str(path) in str(err.value)
    assert path.read_text(encoding="utf-8") == original  # NEVER overwritten


def test_next_number_uses_max_not_len_with_a_missing_row(tmp_path):
    path = tmp_path / "tabel.json"
    # A hand-edited table: object-02 has been removed, object-01 and
    # object-03 remain. len() would want to give "2" here (two rows) and
    # thereby let a NEW name reuse the pseudonym "object-02" - the number
    # the removed object once carried.
    # The table maps pseudonym -> real name (the file on disk is thus
    # REVERSED from the old fixture here - that IS the repair).
    path.write_text(json.dumps({"object-01": "LB_VS_A", "object-03": "LB_VS_C"}), encoding="utf-8")

    render(
        Answer(
            question="v",
            findings=[Finding(subject="LB_VS_NIEUW", outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")],
        ),
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        pseudonym_table_path=path,
    )
    table = json.loads(path.read_text(encoding="utf-8"))
    pseudonym_by_name = {v: k for k, v in table.items()}
    assert pseudonym_by_name["LB_VS_NIEUW"] == "object-04"


def test_identity_and_overlap_do_not_leak_through_the_real_engine(tmp_path):
    """Real-engine proof: a vserver LITERALLY named 'object-01'
    (identity collision - without the repair it receives itself as
    pseudonym, a no-op replacement) plus a second vserver
    'object-02-verlengd' (the overlapping-namespace variant: a generated
    pseudonym must also have no substring relation with ANOTHER real name
    in the collection). Runs through `what_breaks()` for real, not through
    a hand-built Answer fixture."""
    export = _real_export(
        tmp_path,
        bindings={
            "object-01": [{"certkeyname": _CERT, "vservername": "object-01", "snicert": False, "ca": False}],
            "object-02-verlengd": [
                {"certkeyname": _CERT, "vservername": "object-02-verlengd", "snicert": False, "ca": False}
            ],
        },
    )
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    assert {b.subject for b in answer.findings} == {"object-01", "object-02-verlengd"}  # premise

    names = names_from_export(export) + (_CERT,)
    path = tmp_path / "tabel.json"
    text = render(
        answer, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", extra_names=names, pseudonym_table_path=path
    )
    _no_name_leaks(text, names)

    table = json.loads(path.read_text(encoding="utf-8"))  # pseudonym -> real name
    # No identity mapping: a pseudonym may never equal its own real
    # name.
    assert not any(key == value for key, value in table.items())
    # No pseudonym may collide with (equal, or have a substring relation
    # with) ANOTHER real name in the collection.
    for key, own_name in table.items():
        for other_name in table.values():
            if other_name == own_name:
                continue
            assert key != other_name, f"{key} botst met {other_name}"
            assert key not in other_name, f"{key} zit als substring in {other_name}"
            assert other_name not in key, f"{other_name} zit als substring in {key}"


def test_identity_table_is_refused_the_exact_broken_case(tmp_path):
    """The exact proof: a pre-existing, syntactically valid,
    semantically broken table (`{"ZEER_GEHEIM_VSERVER":
    "ZEER_GEHEIM_VSERVER"}`) must be refused fail-closed - not silently
    accepted with the real name leaking in question/subject/outcome/
    evidence."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"ZEER_GEHEIM_VSERVER": "ZEER_GEHEIM_VSERVER"}), encoding="utf-8")

    a = Answer(
        question="wat breekt er als ZEER_GEHEIM_VSERVER verloopt",
        findings=[
            Finding(
                subject="ZEER_GEHEIM_VSERVER",
                outcome="raakt ZEER_GEHEIM_VSERVER",
                certainty=Certainty.ESTABLISHED,
                evidence="binding op ZEER_GEHEIM_VSERVER",
            )
        ],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("ZEER_GEHEIM_VSERVER",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)


def test_duplicate_assignment_is_refused(tmp_path):
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "LB_VS_A", "object-02": "LB_VS_A"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)


def test_old_storage_direction_is_refused(tmp_path):
    """A table in the OLD direction (real name as key) does
    not follow the pseudonym pattern 'object-NN' and is therefore refused,
    not silently read as valid."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"LB_VS_PORTAAL": "object-01"}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)


def test_empty_or_non_text_value_is_refused(tmp_path):
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "   "}), encoding="utf-8")
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)


def test_namespace_collision_with_current_names_is_refused(tmp_path):
    """Not identity WITHIN the same row (the previous test covers that) -
    here an EXISTING pseudonym collides with a NEW real name this call
    processes (cross-row collision)."""
    path = tmp_path / "tabel.json"
    path.write_text(json.dumps({"object-01": "OUDE_NAAM"}), encoding="utf-8")
    a = Answer(
        question="v",
        findings=[Finding(subject="object-01", outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(a, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", pseudonym_table_path=path)
    assert str(path) in str(err.value)


_TWO_PROCESS_WORKER = """
import os
import sys
import time
from pathlib import Path

name = sys.argv[1]
path = Path(sys.argv[2])

delay = os.environ.get("NSMCP_OPENHEID_TESTHAAK_VERTRAGING_S")
if delay:
    _original_read_text = Path.read_text

    def _delayed_read_text(self, *a, **kw):
        result = _original_read_text(self, *a, **kw)
        if self == path:
            time.sleep(float(delay))
        return result

    Path.read_text = _delayed_read_text

from nsmcp.answer import Answer, Finding, Certainty
from nsmcp.disclosure import Disclosure, render

answer = Answer(
    question="v",
    findings=[
        Finding(subject=name, outcome="x", certainty=Certainty.ESTABLISHED, evidence="b")
    ],
)
render(answer, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", pseudonym_table_path=path)
"""


def test_two_processes_lose_no_key(tmp_path):
    """Deterministic two-process regression. `threading.Lock` protects
    only threads WITHIN one process; this spawns two REAL `subprocess`
    worker processes on the SAME table.

    Process A receives `NSMCP_OPENHEID_TESTHAAK_VERTRAGING_S` (read by the
    WORKER, see above - not by nsmcp/disclosure.py itself), which delays
    reading the table. Process B starts shortly after. Without a
    cross-process lock both processes read the same (still empty) table
    and the last writer overwrites the first one's assignment wholesale
    (lost update - historically: both received 'object-01' and one of the
    two names vanished). With the lock, B waits for A's complete
    read-modify-write and both names land in the table, each with its own
    pseudonym."""
    path = tmp_path / "tabel.json"
    path.write_text("{}", encoding="utf-8")  # already exists, so BOTH processes really read
    worker = tmp_path / "worker.py"
    worker.write_text(_TWO_PROCESS_WORKER, encoding="utf-8")

    env_a = dict(os.environ)
    env_a["NSMCP_OPENHEID_TESTHAAK_VERTRAGING_S"] = "0.6"
    proc_a = subprocess.Popen(
        [sys.executable, str(worker), "PROC_A", str(path)],
        env=env_a,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(0.15)  # gives process A the chance to read (and start waiting) before B starts
    proc_b = subprocess.Popen(
        [sys.executable, str(worker), "PROC_B", str(path)],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    output_a, _ = proc_a.communicate(timeout=30)
    output_b, _ = proc_b.communicate(timeout=30)
    assert proc_a.returncode == 0, output_a.decode("utf-8", "replace")
    assert proc_b.returncode == 0, output_b.decode("utf-8", "replace")

    table = json.loads(path.read_text(encoding="utf-8"))
    assert _real_names_from_table(table) == {"PROC_A", "PROC_B"}  # neither name vanished
    assert len(table) == 2  # no two names sharing the same pseudonym


def test_not_established_without_read_gaps_claims_no_yes(tmp_path):
    """Real-engine proof 1: the ca flag is missing on a binding ->
    `what_breaks()` (directly, NOT through `what_to_do()`) yields exactly
    ONE NOT_ESTABLISHED finding and ZERO read gaps - the premise that
    fooled the old count ('there is a finding, so yes')."""
    export = _real_export(
        tmp_path,
        bindings={"LB_VS_PORTAAL": [{"certkeyname": _CERT, "vservername": "LB_VS_PORTAAL", "snicert": False}]},
    )
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    assert answer.read_gaps == []  # premise: no read gaps
    assert len(answer.findings) == 1
    assert answer.findings[0].certainty is Certainty.NOT_ESTABLISHED  # premise

    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "actie nodig: ja" not in text
    assert "actie nodig: niet vast te stellen uit dit antwoord" in text


def test_established_no_bound_vservers_claims_no_yes(tmp_path):
    """Real-engine proof 2: no binding matches the certificate ->
    `what_breaks()` yields exactly ONE ESTABLISHED finding whose OWN TEXT
    says 'geen gebonden virtuele servers en geen uitgegeven certificaten
    gevonden in deze export' (since the chain-aware round that statement
    covers BOTH routes at once), and ZERO read gaps.
    The old count said 'ja' here purely because the findings list had one
    entry - even though the finding itself says there is nothing. After
    the repair 'ja' never appears here again, only the derived, honest
    'mogelijk actie nodig' statement."""
    export = _real_export(
        tmp_path,
        bindings={
            "ANDERE_VSERVER": [
                {"certkeyname": "een_ander_certificaat", "vservername": "ANDERE_VSERVER", "snicert": False, "ca": False}
            ]
        },
    )
    knowledge = _real_knowledge()
    answer = what_breaks(export, knowledge, _CERT)
    assert answer.read_gaps == []  # premise: no read gaps
    assert len(answer.findings) == 1
    assert answer.findings[0].certainty is Certainty.ESTABLISHED  # premise
    assert (
        "geen gebonden virtuele servers en geen uitgegeven certificaten gevonden" in answer.findings[0].outcome
    )  # premise

    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "actie nodig: ja" not in text
    assert "mogelijk actie nodig: er zijn 1 vastgestelde bevinding(en)" in text


def test_own_row_colliding_with_itself_is_refused(tmp_path):
    """The EXACT proof: `_validate_loaded_table()` excluded a row's OWN
    assigned real value from the namespace collision check
    (`overige_namen = alle_echte_namen - {value}`). A syntactically valid
    existing table `{"object-01": "object"}` was thereby accepted: the
    renderer replaced the real name "object" with the pseudonym
    "object-01", which carries the full real name literally as a substring
    - so it stayed readable in every rendered text
    (REAL_NAME_SUBSTRING_IN_OUTPUT).

    Goes through a REAL `render()` call (limited), not an isolated call of
    `_validate_loaded_table()` - the same path as
    `test_identity_table_is_refused_the_exact_broken_case` above.
    Also proves, explicitly as requested: the table file is byte-identical
    before and after the refused attempt (hash + full content), so the
    refusal writes NOTHING."""
    path = tmp_path / "tabel.json"
    tabel_json = json.dumps({"object-01": "object"})
    path.write_text(tabel_json, encoding="utf-8")
    before_bytes = path.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    a = Answer(
        question="wat breekt er als object verloopt",
        findings=[
            Finding(
                subject="object",
                outcome="raakt object",
                certainty=Certainty.ESTABLISHED,
                evidence="binding op object",
            )
        ],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            a, Disclosure.LIMITED, tool="certificaat_wat_breekt_er", extra_names=("object",), pseudonym_table_path=path
        )
    assert str(path) in str(err.value)

    after_bytes = path.read_bytes()
    assert after_bytes == before_bytes, "de vertaaltabel is gewijzigd ondanks de weigering"
    assert hashlib.sha256(after_bytes).hexdigest() == before_hash


def test_reverse_substring_direction_own_row_is_also_refused(tmp_path):
    """The mirror-image variant of the exact case above: here the PSEUDONYM
    itself is the substring of its OWN real value ("object-01" sits inside
    "object-01-reserve"), not the other way around.
    `_collides_with_real_names()` already checks both directions - this
    test proves that the own-row blind spot in the previous check also let
    this direction leak, and that the repair catches this direction too.
    Same byte-identical proof as above."""
    path = tmp_path / "tabel.json"
    tabel_json = json.dumps({"object-01": "object-01-reserve"})
    path.write_text(tabel_json, encoding="utf-8")
    before_bytes = path.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    a = Answer(
        question="wat breekt er als object-01-reserve verloopt",
        findings=[
            Finding(
                subject="object-01-reserve",
                outcome="raakt object-01-reserve",
                certainty=Certainty.ESTABLISHED,
                evidence="binding op object-01-reserve",
            )
        ],
    )
    with pytest.raises(PseudonymTableBroken) as err:
        render(
            a,
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("object-01-reserve",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)

    after_bytes = path.read_bytes()
    assert after_bytes == before_bytes, "de vertaaltabel is gewijzigd ondanks de weigering"
    assert hashlib.sha256(after_bytes).hexdigest() == before_hash


def test_trailing_newline_in_key_is_refused(tmp_path):
    """`re.match()` with a `$` anchor (without MULTILINE) may match just
    BEFORE a trailing newline, not exclusively at the true end of the
    string. A key `"object-01\\n"` was thereby wrongly recognized as a
    valid `object-NN` pattern, written back out, and thus distorts the
    output across lines. `re.fullmatch()` demands that the WHOLE string
    matches and rightly refuses this key. Byte-identical proof as
    above."""
    path = tmp_path / "tabel.json"
    tabel_json = json.dumps({"object-01\n": "LB_VS_PORTAAL"})
    path.write_text(tabel_json, encoding="utf-8")
    before_bytes = path.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    with pytest.raises(PseudonymTableBroken) as err:
        render(
            _answer(),
            Disclosure.LIMITED,
            tool="certificaat_wat_breekt_er",
            extra_names=("wildcard_gjk",),
            pseudonym_table_path=path,
        )
    assert str(path) in str(err.value)
    assert "object-NN" in str(err.value)

    after_bytes = path.read_bytes()
    assert after_bytes == before_bytes, "de vertaaltabel is gewijzigd ondanks de weigering"
    assert hashlib.sha256(after_bytes).hexdigest() == before_hash


def _export_with_target(tmp_path: Path, target_line: str):
    """A minimal REAL export on disk that records a target name, built the
    same way `collect.collect()` does: `scan-doel.txt` line 1 is the name,
    line 2 the sha256 of the manifest it belongs to (see
    `export._read_target_name`)."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    manifest = {
        "manifestVersion": "1.1",
        "collectorVersion": "1.0.0",
        "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
        "resources": {},
        "files": {},
    }
    manifest_path = export_dir / "export-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"{target_line}\n{digest}\n", encoding="utf-8")
    return load_export(export_dir)


def test_target_name_is_masked_at_beperkt_and_hidden_at_minimaal(tmp_path):
    """MEASURED: the OLD version of this test
    built an `Answer` by hand and called `render()` directly - so it could
    only ever see tools that already go through `render()`, and was
    structurally blind to the one registered read tool that does not:
    `status_ververs` kept printing the raw target name at EVERY disclosure
    level while all twelve other tools were already fixed.

    This version drives a REAL MCP session against every REGISTERED read
    tool - the set is DERIVED from `build_server()` itself (never
    hand-written), so a future tool that bypasses `render()` fails this
    test automatically instead of silently passing it. Premise first
    ('volledig' really carries the raw name, for every tool this loop
    calls), then the masked/hidden assertions at 'beperkt'/'minimaal' - in
    the answer TEXT and in `structuredContent`, the two channels this test
    measures.
    """
    import asyncio

    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session
    from test_no_network import REAL_SESSION_READ_TOOL_CALLS, _real_export, _real_knowledge

    from nsmcp.mcp_server import build_server, forget_identities

    target = "labZQ0739QZ"

    def _rescan(arguments, timeout_s):
        # status_ververs's own successful-scan stub (same shape as
        # test_no_network.py's `successful_scan`): collect() itself writes
        # scan-doel.txt from the configured Target.name, never from this
        # manifest, so the re-scanned export records the same target.
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "objects").mkdir(parents=True, exist_ok=True)
        (out / "bindings").mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "manifestVersion": "1.1",
                    "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                    "resources": {"config/sslcertkey": {"status": "EMPTY"}},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    read_args = {name: dict(args) for name, args in REAL_SESSION_READ_TOOL_CALLS}
    read_args["status_ververs"] = {"doelnaam": target}
    read_args["status_update_preflight"] = {}

    script = tmp_path / "verzamelscript.ps1"
    script.write_text("# leeg; draai() neemt het over in de test", encoding="utf-8")

    def _build(level: Disclosure, tag: str):
        # A SEPARATE export/target tree per disclosure level: status_ververs
        # swaps export_dir in place on a successful scan, so sharing one
        # directory across levels would let a later level see the PREVIOUS
        # level's freshly-scanned (and possibly reordered-call) state
        # instead of a clean, independent one.
        level_dir = tmp_path / tag
        export_dir = _real_export(level_dir)
        digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
        (export_dir / "scan-doel.txt").write_text(f"{target}\n{digest}\n", encoding="utf-8")
        record_collected(export_dir, target)
        targets_path = level_dir / "doelen.json"
        targets_path.write_text(
            json.dumps(
                {
                    "doelen": [
                        {
                            "naam": target,
                            "adres": "10.0.0.10",
                            "credentialTarget": "gjk/netscaler/lab/readonly",
                            "certificaat": "keten",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        forget_identities()
        return build_server(
            export_dir,
            _real_knowledge(level_dir),
            disclosure=level,
            pseudonym_table_path=level_dir / "tabel.json",
            targets_path=targets_path,
            collect_script=script,
            run=_rescan,
            onderhoud=maintenance_config(level_dir),
            provenance_dir=provenance_dir_for(export_dir),
        )

    async def _call_all(server, tool_names):
        answers = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for name in tool_names:
                r = await client.call_tool(name, read_args[name])
                text = " ".join(b.text for b in r.content if hasattr(b, "text"))
                structured = json.dumps(r.structuredContent or {})
                answers[name] = (r.isError, text, structured)
        return answers

    full_server = _build(Disclosure.FULL, "volledig")
    read_tools = {t.name for t in full_server._tool_manager.list_tools()}
    # PREMISE: this loop's own argument mapping covers EXACTLY the
    # registered tool set - not a hand-picked subset. A read tool added to
    # build_server() and forgotten here fails HERE, loudly, instead of
    # silently never being exercised by this test (the exact shape of the
    # old defect: a test that can only see what it already knew to build).
    assert set(read_args) == read_tools

    volledig = asyncio.run(_call_all(full_server, read_tools))
    for name, (error, text, _structured) in volledig.items():
        assert error is False, f"{name} gaf een fout terug bij 'volledig': {text}"
    # kennis_uitleg is the ONE documented exception (mcp_server.py, its own
    # comment: "this tool never touches the export") - a pure glossary
    # lookup that never calls stamp_data()/render() at all, so it carries no
    # "doel: ..." line at any level and has nothing for this test to prove
    # a premise about. Every OTHER registered read tool does stamp the
    # target - pinned as a count (not just "at least one"), so a second tool
    # quietly losing its stamp fails here by name instead of being absorbed
    # into a soft "most of them" check.
    carries_stamp = {name for name, (_, text, _) in volledig.items() if "doel:" in text}
    assert carries_stamp == read_tools - {"kennis_uitleg"}, (
        f"onverwachte tools zonder doel-stempel: {read_tools - {'kennis_uitleg'} - carries_stamp}"
    )
    for name in carries_stamp:
        text, structured = volledig[name][1], volledig[name][2]
        assert f"doel: {target}" in text, f"{name}: premise faalt, geen doelnaam bij 'volledig' (tekst)"
        assert f"doel: {target}" in structured, (
            f"{name}: premise faalt, geen doelnaam bij 'volledig' (structuredContent)"
        )

    # The MARKER checked below is the closing "doel: ..." stamp specifically
    # - not a blanket absence of the raw string. status_ververs's own
    # confirmation sentence ("De scan van '<doelnaam>' is gelukt.") echoes
    # the CALLER'S OWN `doelnaam` argument, which for this test equals
    # `target` - that echo discloses nothing the caller did not just type
    # ("honest qualification 1") and is
    # deliberately out of scope for this fix. The stamp line is the thing
    # that must be masked, for every tool, including this one.
    marker = f"doel: {target}"

    beperkt = asyncio.run(_call_all(_build(Disclosure.LIMITED, "beperkt"), read_tools))
    for name, (error, text, structured) in beperkt.items():
        assert error is False, f"{name} gaf een fout terug bij 'beperkt': {text}"
        assert marker not in text, f"{name}: doelnaam lekt onvermomd bij 'beperkt' (tekst)"
        assert marker not in structured, f"{name}: doelnaam lekt onvermomd bij 'beperkt' (structuredContent)"

    minimaal = asyncio.run(_call_all(_build(Disclosure.MINIMAL, "minimaal"), read_tools))
    for name, (error, text, structured) in minimaal.items():
        assert error is False, f"{name} gaf een fout terug bij 'minimaal': {text}"
        assert marker not in text, f"{name}: doelnaam lekt onvermomd bij 'minimaal' (tekst)"
        assert marker not in structured, f"{name}: doelnaam lekt onvermomd bij 'minimaal' (structuredContent)"


def test_absent_target_name_still_says_not_recorded_not_hidden(tmp_path):
    """Negative check: a SUPPLIED export (no scan-doel.txt) has no target
    name at all - `minimaal` must keep the honest 'niet vastgelegd', not the
    new 'niet getoond op deze stand' (there is nothing recorded to hide)."""
    from datetime import date

    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectorVersion": "1.0.0",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    export = load_export(export_dir)
    assert export.target_name is None  # premise: nothing recorded

    base = Answer(question="status_namen")
    answer = stamp_data(base, export.collected_at, date(2026, 9, 6), export.target_name)

    minimal = render(answer, Disclosure.MINIMAL, tool="status_namen")
    assert "doel: niet vastgelegd." in minimal
    assert "niet getoond op deze stand" not in minimal


def test_status_ververs_unknown_target_enumeration_is_only_at_volledig(tmp_path):
    """The WORSE half of C1: 'Onbekend doel ...'
    used to enumerate every CONFIGURED target name - names the caller never
    even asked about - at EVERY disclosure level, a de-pseudonymisation
    oracle for exactly the value the closing-stamp fix above pseudonymises.

    The writing tools already solve this shape: `handelen.validate()`'s
    allowlist refusal names real object names, so those four tools exist
    only at 'volledig' (see the disclosure gate on the writing tools,
    `mcp_server.py`, docs/klant/SECURITY.md:41-43). This follows the same
    rule for the SAME reason: the enumeration stays at 'volledig' (the
    existing pattern), and is withheld at 'beperkt'/'minimaal'.
    """
    import asyncio

    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    from nsmcp.mcp_server import build_server, forget_identities

    real, other = "labZQ0739QZ", "prodWX4411XW"
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectorVersion": "1.0.0",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    knowledge_path = tmp_path / "kennis.json"
    knowledge_path.write_text(json.dumps({"versie": "2026.08", "datum": "2026-08-16"}), encoding="utf-8")
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": real,
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    },
                    {
                        "naam": other,
                        "adres": "10.0.0.11",
                        "credentialTarget": "gjk/netscaler/prod/readonly",
                        "certificaat": "keten",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    script = tmp_path / "verzamelscript.ps1"
    script.write_text("# nooit uitgevoerd in deze test", encoding="utf-8")

    async def _ask(level: Disclosure) -> str:
        forget_identities()
        server = build_server(
            export_dir,
            knowledge_path,
            disclosure=level,
            pseudonym_table_path=tmp_path / f"tabel-{level.value}.json",
            targets_path=targets_path,
            collect_script=script,
        )
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            r = await client.call_tool("status_ververs", {"doelnaam": "raadsel"})
            return " ".join(b.text for b in r.content if hasattr(b, "text"))

    volledig = asyncio.run(_ask(Disclosure.FULL))
    assert real in volledig and other in volledig, "premise faalt: 'volledig' toont de allowlist niet"

    beperkt = asyncio.run(_ask(Disclosure.LIMITED))
    assert real not in beperkt and other not in beperkt, "de allowlist lekt bij 'beperkt'"

    minimaal = asyncio.run(_ask(Disclosure.MINIMAL))
    assert real not in minimaal and other not in minimaal, "de allowlist lekt bij 'minimaal'"


# ---------------------------------------------------------------------------
# The aggregate binding family: every parent name and identity field of the
# aggregate by-parent files the tools READ (`Export.binding_names`, over
# `disclosure.AGGREGATE_BINDING_FILES`). MEASURED on the DoH fixture before
# this family existed: the eight service names bound to ns-server-certificate
# in sslcertkey_binding.by-parent.json and the ipv46 of the one service binding
# in lbvserver_binding.by-parent.json were in no family - and the certificate
# tools print the first kind.
# ---------------------------------------------------------------------------

_DOH = Path(__file__).parent / "fixtures" / "lab-export-vpx-doh-synthetic"


def test_the_aggregate_binding_family_covers_the_certificate_service_names():
    from nsmcp.disclosure import AGGREGATE_BINDING_FILES

    export = load_export(_DOH)
    family = export.binding_names(AGGREGATE_BINDING_FILES)
    for name in ("nshttps-127.0.0.1-443", "nsrpcs-::1l-3008", "nsrnatsip-127.0.0.1-5061", "SRV-WEB-001"):
        assert name in family, name
        assert name in names_from_export(export), name


def test_the_aggregate_binding_family_reads_the_files_the_tools_read():
    """The list-shaped files have their own families (the vserver family
    reads sslvserver_sslcertkey_binding); this family adds the aggregate
    files the chain, the certificate tools and the health snapshot read.

    Moved pin: `csvserver_binding.by-parent.json` joined this tuple with no
    code change to `disclosure.py` itself - `AGGREGATE_BINDING_FILES` is
    DERIVED from `ENTRY_RESOURCES` minus `NOT_FOLLOWED` (this module's own
    comment: "a chain that starts following another entry kind is masked
    the day it does"), and a contentswitching-vserver is no longer in
    `NOT_FOLLOWED` now that `dienst_keten` follows its route."""
    from nsmcp.disclosure import AGGREGATE_BINDING_FILES

    assert AGGREGATE_BINDING_FILES == (
        "csvserver_binding.by-parent.json",
        "lbvserver_binding.by-parent.json",
        "servicegroup_binding.by-parent.json",
        "sslcertkey_binding.by-parent.json",
    )
    export = load_export(_DOH)
    family = set(export.binding_names(AGGREGATE_BINDING_FILES))
    assert "LBV-APP-001" in family and "SG-APP-001" in family and "SRV-APP-001" in family
    assert "198.51.100.10" in family, "het adres van een lid op IP"
    assert "CSV-WEB-001" in family and "LBV-APP-002" in family, (
        "de eigen naam en het standaard-LB-doel van een cs-binding"
    )
    # `policyname` is not one of `BINDING_NAME_FIELDS`: this specific family
    # does not carry a beleidsnaam. A policy name still reaches masking -
    # through `chain.names_in_chain_sources()` and, when it surfaces only in
    # a read-gap reason, through the direct cspolicy/csaction harvest in
    # that same function - the SAME two-mechanism split `names_from_export()`
    # already has for every other family this module reads. Proven positively
    # (not by absence here) in test_chain.py::test_names_in_chain_sources_
    # covers_a_cs_route_and_its_policy_names and ::test_an_action_name_in_an_
    # unresolved_policy_reason_is_masked_at_beperkt.
    assert "CSPOL-001" in set(names_from_export(export)), "een beleidsnaam bereikt names_from_export() via chain.py"


def test_a_vendor_monitor_name_never_enters_the_name_set():
    """MEASURED while building this family: harvesting EVERY aggregate file
    also took the parent list of lbmonitor_binding - the appliance's built-in
    monitors, among them "sta", "ping", "http" and "tcp". Every name is
    replaced as a substring at 'beperkt', so "sta" turned "geforceerde stand"
    in ha_stand into "geforceerde object-75nd". No tool prints a monitor name
    out of these files, so none of them is collected."""
    for root in (_DOH, Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"):
        names = set(names_from_export(load_export(root)))
        for monitor in ("sta", "ping", "http", "tcp", "dns", "arp"):
            assert monitor not in names, (root.name, monitor)


def _pinned_product_sentences() -> set[str]:
    """Every Dutch sentence tests/test_product_surface.py pins with
    `assert ... == "..."` (either side of the `==`): parsed with `ast`
    rather than grepped, so a literal sitting inside a docstring or a
    comment is not product text and does not count. Filtered to values that
    carry a space - a bare identifier pinned the same way ("LBV-070" in a
    membership check) is not a Dutch sentence a real name could corrupt."""
    import ast

    src = (Path(__file__).parent / "test_product_surface.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    sentences: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            for side in (node.left, node.comparators[0]):
                if isinstance(side, ast.Constant) and isinstance(side.value, str) and " " in side.value:
                    sentences.add(side.value)
    return sentences


# Named exceptions for the canary below: (name, a distinguishing SUBSTRING
# of the one sentence it excuses) - never the bare name, so an exception
# can never swallow a collision between that name and a DIFFERENT sentence
# (the historical risk: a short real name inside an unrelated Dutch word,
# e.g. "labelwissel" or "labbewijs" - see the mechanism reasoning on the
# test below). `start._require_safe_upgrade_target_names()` echoes an
# OPERATOR-CONFIGURED doelnaam ("lab02.") straight into a startup
# `ConfigError`, before any export loads and before this seam ever runs at
# all - not a text `render()` ever masks. The real target name of
# tests/fixtures/lab-export-vpx-20260826 ("lab") sits inside that unrelated
# synthetic example purely by coincidence of two short, independently-chosen
# names - proven harmless below, not just excused, and the canary itself
# asserts that this pairing still actually occurs (a stale exception that
# matches nothing any more fails loudly instead of sitting there unused).
NAMED_EXCEPTIONS = frozenset({("lab", "lab02.")})


def _embedded_name_hits(
    names: set[str], sentences: set[str], exceptions: frozenset[tuple[str, str]]
) -> tuple[list[tuple[str, str]], set[tuple[str, str]]]:
    """The canary's search: every name of two or more characters that sits
    INSIDE a word of a sentence (a word character on at least one side) is a
    hit, unless an exception for that name matches AT THAT POSITION. Bound
    to the match position on purpose: an exception that merely occurs
    somewhere in the sentence would also excuse a second, unrelated hit of
    the same name later in that sentence (measured: "doel lab02." used to
    excuse the "lab" inside "policylabel" in the same sentence)."""
    hits: list[tuple[str, str]] = []
    excused: set[tuple[str, str]] = set()
    for name in names:
        if len(name) < 2:
            continue
        pattern = re.compile(re.escape(name))
        for sentence in sentences:
            for m in pattern.finditer(sentence):
                start, end = m.span()
                left_word = start > 0 and (sentence[start - 1].isalnum() or sentence[start - 1] == "_")
                right_word = end < len(sentence) and (sentence[end].isalnum() or sentence[end] == "_")
                if not (left_word or right_word):
                    continue
                exception = next(
                    (exc for exc in exceptions if exc[0] == name and sentence.startswith(exc[1], start)),
                    None,
                )
                if exception is not None:
                    excused.add(exception)
                    continue
                hits.append((name, sentence))
    return hits, excused


def test_canary_exception_is_bound_to_its_match_position():
    """An excused form excuses exactly one occurrence: the one that starts
    at the excused text. A second hit of the same name elsewhere in that
    sentence, and any hit in a sentence without the excused form, still
    trip the canary."""
    exceptions = frozenset({("lab", "lab02.")})
    hits, excused = _embedded_name_hits({"lab"}, {"doel lab02."}, exceptions)
    assert hits == [] and excused == exceptions
    hits, excused = _embedded_name_hits({"lab"}, {"doel lab02. staat in een policylabel"}, exceptions)
    assert hits == [("lab", "doel lab02. staat in een policylabel")] and excused == exceptions
    hits, excused = _embedded_name_hits({"lab"}, {"de policylabel staat aan"}, exceptions)
    assert hits == [("lab", "de policylabel staat aan")] and excused == set()


def test_no_harvested_name_corrupts_a_pinned_dutch_sentence(tmp_path):
    """Structural canary: the test above closes the MEASURED TRIGGER for a
    real name breaking ordinary Dutch text ("sta" inside "geforceerde
    stand"), not the mechanism: `_replacement_pattern()` (disclosure.py)
    gives a word boundary only to `caller_name` (the `word_bounded`
    branch) - every name in `extra_names`, the STRUCTURAL harvest from
    `names_from_export()`, is still replaced as a bare substring, and that
    is not an oversight but a necessity: `backup.backup_name()` forms
    "gjk_preupgrade_<doel>_<stamp>", the doelnaam flanked by '_' - a WORD
    character - on both sides, so a word-bounded pattern would leave a
    target name embedded there UNMASKED, the opposite leak. Word boundaries
    for real names are therefore not an available fix (measured, not
    assumed - see the reasoning above); the harvest is the only place left
    to catch a short name that happens to sit inside ordinary product text,
    the same risk class as "sta"/"stand" or a hypothetical "up"/"update".

    MEASURED: every name `names_from_export()` harvests from BOTH lab
    fixtures, checked against every Dutch sentence tests/test_product_
    surface.py pins with `assert ... == "..."` (parsed with `ast`, not
    grepped - a literal sitting inside a docstring or a comment is not
    product text and must not count), embeds in none of them today except
    `NAMED_EXCEPTIONS` above - each checked per SENTENCE, not per name, so a
    name excused in one sentence still trips the canary in any other. A name
    that stands ALONE as a complete token in a sentence (an example value
    such as "192.0.2.x" or "lab-02") is deliberately not counted here: that
    is a name printed as a name in product copy, not a word it corrupts,
    and it is proven masked-when-standalone below, for the one short case
    ("lab") that could plausibly collide with an ordinary Dutch word too."""
    names: set[str] = set()
    for root in (_DOH, Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"):
        harvested = set(names_from_export(load_export(root)))
        assert len(harvested) > 20, (
            root.name,
            "te weinig geoogste namen; wijst op een lege of verkeerd verwezen fixturemap",
        )
        names |= harvested
    assert "lab" in names, "de doelnaam 'lab' ontbreekt uit de oogst; het bewijs verderop test dan niets echts"

    sentences = _pinned_product_sentences()
    assert len(sentences) > 100, "geen of te weinig gepinde Nederlandse zinnen gevonden; parser stuk?"

    hits, excused = _embedded_name_hits(names, sentences, NAMED_EXCEPTIONS)
    assert not hits, hits
    assert excused == NAMED_EXCEPTIONS, (
        f"een benoemde uitzondering raakt niets (verouderd) of werd niet gevonden: {set(NAMED_EXCEPTIONS) ^ excused}"
    )

    # Being short is a reason for this canary to double-check a name, never
    # a reason for `render()` to skip masking it. "lab" - a REAL harvested
    # name, and the one name a `NAMED_EXCEPTIONS` entry excuses above - is
    # still masked as a standalone token, so that exception excuses one
    # coincidental sentence, never the name itself.
    a = Answer(
        question="v",
        findings=[
            Finding(
                subject="uitkomst",
                outcome="doel lab bereikt",
                certainty=Certainty.ESTABLISHED,
                evidence="schrijfscript",
                subject_is_name=False,
            )
        ],
    )
    text = render(
        a,
        Disclosure.LIMITED,
        tool="dienst_status",
        extra_names=("lab",),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "lab" not in text, text
    assert "object-" in text, text


def test_the_aggregate_binding_family_harvests_an_unusable_file_too(tmp_path):
    """Tolerant by design: a read gap on this file NAMES a parent ("dubbele
    parent X"), so a harvest that fell silent on an unusable file would leak
    exactly the name the gap makes visible."""
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    parent = {
        "parentName": "LBV-DUBBEL",
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": "LBV-DUBBEL", "lbvserver_service_binding": [{"servicename": "SVC-X"}]}},
    }
    raw = json.dumps(
        {
            "bindingResource": "lbvserver_binding",
            "parentResource": "lbvserver",
            "parentKey": "name",
            "shape": "aggregate",
            "parents": [parent, parent],
        }
    )
    (m / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-24T06:00:00.0000000Z",
        "resources": {},
        "files": {"bindings/lbvserver_binding.by-parent.json": hashlib.sha256(raw.encode("utf-8")).hexdigest()},
    }
    (m / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    export = load_export(m)
    assert export.binding_rows("lbvserver_binding.by-parent.json", children=("lbvserver_service_binding",))[1]
    assert set(export.binding_names(("lbvserver_binding.by-parent.json",))) == {"LBV-DUBBEL", "SVC-X"}


def _real_names_in_the_doh_export() -> set[str]:
    """Every name-carrying field value of the DoH fixture's binding files and
    of the object sources the five tools below read - the names a 'beperkt'
    answer may never carry."""
    fields = (
        "name",
        "servicename",
        "servername",
        "servicegroupname",
        "vservername",
        "lbvserver",
        "ip",
        "ipv46",
        "ipaddress",
        "certkey",
        "parentName",
    )
    found: set[str] = set()

    def walk(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                if key in fields and isinstance(inner, str) and inner.strip():
                    found.add(inner.strip())
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    sources = list((_DOH / "bindings").glob("*.json"))
    sources += [
        _DOH / "objects" / f"{n}.json" for n in ("lbvserver", "csvserver", "servicegroup", "service", "sslcertkey")
    ]
    for path in sources:
        walk(json.loads(path.read_text(encoding="utf-8")))
    return found


def test_no_real_name_reaches_a_limited_answer_of_the_aggregate_reading_tools(tmp_path):
    """The five tools that read the aggregate shape through the shared
    reader, on the DoH export, at 'beperkt': not one real name, standing on
    its own, in any of them. The management refusal of the advice quotes the
    service names, and only the aggregate binding family knows those."""
    from nsmcp.chain import service_chain
    from nsmcp.coverage import coverage_answer
    from nsmcp.health import health_answer

    export = load_export(_DOH)
    knowledge = Knowledge(version="x", date="2026-09-06", age_days=0, missing=False)
    certname = "ns-server-certificate"
    answers = {
        "dienst_keten": service_chain(export, knowledge, ""),
        "certificaat_wat_verloopt_er": what_expires(export, knowledge, 3650000),
        "certificaat_wat_breekt_er": what_breaks(export, knowledge, certname),
        "certificaat_wat_moet_ik_doen": what_to_do(what_breaks(export, knowledge, certname), knowledge, certname),
        "status_gezondheid": health_answer(export, knowledge),
        "rapport_dekking": coverage_answer(export, knowledge),
    }
    real = _real_names_in_the_doh_export()
    assert {"nshttps-127.0.0.1-443", "SG-APP-001", "SRV-APP-001", "LBV-APP-001"} <= real, "premisse"
    for tool, answer in answers.items():
        full = render(answer, Disclosure.FULL, tool=tool, extra_names=names_from_export(export), caller_name=certname)
        limited = render(
            answer,
            Disclosure.LIMITED,
            tool=tool,
            extra_names=names_from_export(export),
            caller_name=certname,
            pseudonym_table_path=tmp_path / f"tabel-{tool}.json",
        )
        shown = [n for n in real if re.search(rf"(?<!\w){re.escape(n)}(?!\w)", full)]
        # rapport_dekking names no parent on this export (its two gaps are
        # collector facts); every other tool does at 'volledig'.
        assert shown or tool == "rapport_dekking", f"{tool}: zonder echte namen bij volledig bewijst dit niets"
        leaked = sorted(n for n in real if re.search(rf"(?<!\w){re.escape(n)}(?!\w)", limited))
        assert leaked == [], f"{tool} lekt bij beperkt: {leaked}"


def test_the_aggregate_binding_family_reads_nothing_it_cannot_trust(tmp_path):
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    raw = json.dumps(
        {
            "bindingResource": "lbvserver_binding",
            "shape": "aggregate",
            "parents": [{"parentName": "LBV-GEHEIM", "outcome": "OK", "data": {"lbvserver_binding": {"name": "x"}}}],
        }
    )
    (m / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-24T06:00:00.0000000Z",
        "resources": {},
        "files": {"bindings/lbvserver_binding.by-parent.json": "0" * 64},
    }
    (m / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert load_export(m).binding_names(("lbvserver_binding.by-parent.json",)) == ()
