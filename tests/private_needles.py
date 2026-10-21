"""Search terms that name the maintainers' own environment, read from OUTSIDE
the tracked tree.

Several hygiene guards search the tree for names that must not be in it: a
local working directory, a folder that never ships, the name of a tool or a
model used while building, an internal working name. A guard cannot type
such a name without publishing it itself, and spelling it in two halves
only hides it from a search, not from a reader. So the names live in a file
that is not part of the repository:

- the path in the environment variable `NSMCP_PRIVATE_NEEDLES`, or else
- `.private-needles.txt` in the repository root (ignored by git).

One needle per line as `<category>: <value>`; blank lines and lines starting
with `#` are ignored. The categories the guards read are `pad` (a directory
directly under a drive root), `map` (a folder path that never ships),
`naam` (a tool, model or service name) and `werknaam` (the working name of
the product). A guard that has no needles for its category skips with a
reason that says so: on a fresh clone and in CI the guard is then silent
rather than falsely green, and the structural checks next to it still run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ENV = "NSMCP_PRIVATE_NEEDLES"
DEFAULT_FILE = Path(__file__).resolve().parent.parent / ".private-needles.txt"
CATEGORIES = ("pad", "map", "naam", "werknaam")


def _source() -> Path | None:
    configured = os.environ.get(ENV, "").strip()
    if configured:
        return Path(configured)
    return DEFAULT_FILE if DEFAULT_FILE.is_file() else None


def parse(text: str) -> dict[str, tuple[str, ...]]:
    """`<category>: <value>` lines to a tuple of values per category; an
    unknown category or a line without a colon is an error, never a silent
    drop - a typo would otherwise switch a guard off."""
    found: dict[str, list[str]] = {category: [] for category in CATEGORIES}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        category, separator, value = line.partition(":")
        category, value = category.strip(), value.strip()
        if not separator or category not in found or not value:
            raise ValueError(f"regel {number} van de needle-lijst heeft niet de vorm '<categorie>: <waarde>'")
        found[category].append(value)
    return {category: tuple(values) for category, values in found.items()}


def private_needles(category: str) -> tuple[str, ...]:
    """The needles of `category`, or an empty tuple when no list is present."""
    if category not in CATEGORIES:
        raise ValueError(f"onbekende categorie: {category}")
    source = _source()
    if source is None:
        return ()
    return parse(source.read_text(encoding="utf-8"))[category]


def needles_or_skip(category: str) -> tuple[str, ...]:
    needles = private_needles(category)
    if not needles:
        pytest.skip(
            f"geen needles van categorie '{category}': zet {ENV} of leg .private-needles.txt aan"
            " (zie tests/private_needles.py)"
        )
    return needles
