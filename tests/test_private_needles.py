"""The reader of the needle list that lives outside the tracked tree."""

from __future__ import annotations

import pytest
from private_needles import ENV, parse, private_needles


def test_a_needle_list_is_read_per_category():
    text = "# commentaar\n\npad: Werkmap\nnaam: hulpmiddel\nnaam: Tweede\n"
    assert parse(text) == {"pad": ("Werkmap",), "map": (), "naam": ("hulpmiddel", "Tweede"), "werknaam": ()}


@pytest.mark.parametrize("line", ["onbekend: x", "zonder dubbele punt", "pad:"])
def test_a_malformed_line_is_an_error_never_a_silent_drop(line):
    with pytest.raises(ValueError, match="regel 1"):
        parse(line + "\n")


def test_the_environment_variable_names_the_file(tmp_path, monkeypatch):
    lijst = tmp_path / "needles.txt"
    lijst.write_text("map: voorbeeld/map\n", encoding="utf-8")
    monkeypatch.setenv(ENV, str(lijst))
    assert private_needles("map") == ("voorbeeld/map",)
    with pytest.raises(ValueError, match="onbekende categorie"):
        private_needles("iets")
