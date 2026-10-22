"""1.0.3 Minor: an intended pseudonym-table refusal passes the same character
filter as every answer.

MEASURED before (1.0.2): a table configured under a path component carrying
U+202E, with its `.lock` path a directory, gave `isError=true` with the
unfiltered path in the text: `mask_error` passes an intended ToolError
through unchanged, so that text never reached `Answer.to_text()`. The
refusal messages of the table now go through `safe_text` where they are
built (the exception classes themselves), so every raise site is covered.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from test_binding_parent_position import _export, _knowledge

from nsmcp.disclosure import Disclosure, PseudonymTableBroken, PseudonymTableLocked
from nsmcp.limits import HIDDEN_CHARACTER_MARK
from nsmcp.mcp_server import build_server, forget_identities

_HIDDEN = ("\u202e", "\u200b")


def _call(server) -> tuple[bool, str]:
    async def run():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="test-client", version="1")
        ) as client:
            result = await client.call_tool("certificaat_wat_breekt_er", {"certnaam": "cert_fixture"})
            return result.isError, "\n".join(block.text for block in result.content if hasattr(block, "text"))

    return asyncio.run(run())


def _table_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "pad-\u202eproef\u200b"
    directory.mkdir()
    return directory


def _server(tmp_path: Path, table: Path):
    forget_identities()
    export_dir = _export(tmp_path, [{"parentName": "P", "outcome": "EMPTY", "data": None}])
    return build_server(export_dir, _knowledge(tmp_path), disclosure=Disclosure.LIMITED, pseudonym_table_path=table)


def test_a_lock_refusal_does_not_carry_a_hidden_character(tmp_path):
    table = _table_dir(tmp_path) / "tabel.json"
    Path(str(table) + ".lock").mkdir()
    is_error, text = _call(_server(tmp_path, table))
    assert is_error is True, text
    assert "kon niet geopend worden" in text, text
    assert not any(c in text for c in _HIDDEN), ascii(text)
    # The path stays recognisable, with the hidden characters made visible.
    assert f"pad-{HIDDEN_CHARACTER_MARK}proef{HIDDEN_CHARACTER_MARK}" in text, ascii(text)


def test_a_broken_table_refusal_does_not_carry_a_hidden_character(tmp_path):
    table = _table_dir(tmp_path) / "tabel.json"
    table.write_text("{niet: json", encoding="utf-8")
    is_error, text = _call(_server(tmp_path, table))
    assert is_error is True, text
    assert "niet leesbaar als JSON" in text, text
    assert not any(c in text for c in _HIDDEN), ascii(text)


@pytest.mark.parametrize("error", [PseudonymTableBroken, PseudonymTableLocked])
def test_the_filter_sits_in_the_exception_itself(error):
    """Every raise site, also a later one: the class filters its message."""
    message = str(error("pad C:\\a\u202eb\u200bc\\tabel.json kon niet gelezen worden"))
    assert not any(c in message for c in _HIDDEN), ascii(message)
    assert "kon niet gelezen worden" in message
