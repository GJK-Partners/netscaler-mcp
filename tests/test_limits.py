"""The input ceilings, measured rather than guessed.

Without them the readers accepted anything: 100.000 objects out of one file,
a 20 MB `uitleg` field travelling to the model, and 60.000 levels of nesting
that raised a RecursionError past the fail-closed handling.
"""

from __future__ import annotations

from nsmcp.limits import (
    MAX_FILE_BYTES,
    MAX_FREE_TEXT_CHARS,
    MAX_JSON_DEPTH,
    MAX_KNOWLEDGE_TEXT_CHARS,
    MAX_OBJECTS_PER_FILE,
    MAX_TEXT_LINES,
    TRUNCATION_NOTE,
    capped_text,
    exceeds_depth,
)


def test_the_ceilings_are_the_values_the_design_fixed():
    assert MAX_FILE_BYTES == 33554432
    assert MAX_OBJECTS_PER_FILE == 50000
    assert MAX_TEXT_LINES == 100000
    assert MAX_JSON_DEPTH == 100
    assert MAX_FREE_TEXT_CHARS == 8192
    assert MAX_KNOWLEDGE_TEXT_CHARS == 65536


def test_an_ordinary_document_is_not_too_deep():
    assert exceeds_depth({"a": [{"b": ["c"]}]}) is False


def test_a_document_deeper_than_the_limit_is_reported():
    deep = "x"
    for _ in range(MAX_JSON_DEPTH + 5):
        deep = [deep]
    assert exceeds_depth(deep) is True


def test_the_depth_check_never_recurses_itself():
    """A recursive depth check would blow up on exactly the input it exists to
    refuse. This one walks with its own stack, so a 5000-deep document is
    answered rather than raised."""
    deep = "x"
    for _ in range(5000):
        deep = {"k": deep}
    assert exceeds_depth(deep) is True


def test_a_document_exactly_at_the_refusing_depth_is_reported():
    """The walk seeds the root at depth 1, and a leaf scalar is popped and
    counted as one more level like any other node. So a scalar wrapped in
    exactly `limit` containers sits at depth `limit + 1`, which is already
    past `limit` - this is the shallowest scalar-leaf shape that refuses."""
    limit = 5
    deep = "x"
    for _ in range(limit):
        deep = [deep]
    assert exceeds_depth(deep, limit=limit) is True


def test_a_document_one_level_shallower_than_the_refusing_depth_is_accepted():
    """One fewer container puts the same scalar leaf at depth `limit` exactly
    (root seeds at depth 1, the leaf itself is the last level counted), and
    the check only refuses depths strictly greater than `limit` - so this
    shape, one level shallower than the previous test, is not reported."""
    limit = 5
    deep = "x"
    for _ in range(limit - 1):
        deep = [deep]
    assert exceeds_depth(deep, limit=limit) is False


def test_an_empty_innermost_container_flips_one_level_later():
    """An empty container never pushes a leaf on top of itself, so it does not
    get the extra "leaf counts as a level" depth that a scalar leaf gets. The
    container itself is still checked at its own depth, so the flip from
    accepted to refused needs one more nesting level than the scalar-leaf
    shape above: `limit` containers around an empty innermost one is still
    accepted, `limit + 1` is refused."""
    limit = 5
    accepted = []
    for _ in range(limit - 1):
        accepted = [accepted]
    assert exceeds_depth(accepted, limit=limit) is False

    refused = []
    for _ in range(limit):
        refused = [refused]
    assert exceeds_depth(refused, limit=limit) is True


def test_text_within_the_cap_is_returned_untouched():
    text, truncated = capped_text("gewone uitleg")
    assert text == "gewone uitleg"
    assert truncated is False


def test_text_above_the_cap_is_truncated_and_says_so():
    text, truncated = capped_text("a" * (MAX_FREE_TEXT_CHARS + 10))
    assert truncated is True
    assert text.endswith(TRUNCATION_NOTE)
    assert "afgekapt" in text
    assert len(text) == MAX_FREE_TEXT_CHARS + len(TRUNCATION_NOTE)


def test_capped_text_honors_an_explicit_non_default_cap():
    """The cap keyword is part of the published interface: a caller such as
    the knowledge package passes its own limit instead of the module default,
    and that path has to actually use it rather than silently falling back to
    MAX_FREE_TEXT_CHARS."""
    cap = 20
    text, truncated = capped_text("a" * (cap + 10), cap=cap)
    assert truncated is True
    assert text.endswith(TRUNCATION_NOTE)
    assert len(text) == cap + len(TRUNCATION_NOTE)


def test_line_endings_are_normalized_so_a_field_cannot_forge_a_new_answer_line():
    text, _ = capped_text("regel een\r\nregel twee\rregel drie")
    assert "\r" not in text
    assert text == "regel een\nregel twee\nregel drie"
