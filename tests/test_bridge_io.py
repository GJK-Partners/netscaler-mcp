"""The bridges' stdin reader accepts what Windows PowerShell 5.1 actually
sends on a UTF-8 console: the JSON with a byte-order mark in front."""

from __future__ import annotations

import io
import sys

from nsmcp.bridge_io import read_stdin_text

BOM = b"\xef\xbb\xbf"
JSON_BYTES = b'{"actie":"vorm","verzoeken":[]}\r\n'


def _with_stdin(stream):
    real = sys.stdin
    sys.stdin = stream
    try:
        return read_stdin_text()
    finally:
        sys.stdin = real


def test_a_byte_order_mark_from_a_utf8_console_is_stripped_under_a_cp1252_text_layer():
    """The measured runner shape: BOM bytes underneath a cp1252 text wrapper.
    A text-mode read would yield three stray characters before the JSON."""
    stream = io.TextIOWrapper(io.BytesIO(BOM + JSON_BYTES), encoding="cp1252")
    assert _with_stdin(stream) == JSON_BYTES.decode("ascii")


def test_input_without_a_mark_is_read_unchanged():
    stream = io.TextIOWrapper(io.BytesIO(JSON_BYTES), encoding="cp1252")
    assert _with_stdin(stream) == JSON_BYTES.decode("ascii")


def test_a_text_only_stdin_also_loses_a_leading_mark():
    """Under test `sys.stdin` is often a StringIO without a byte buffer."""
    assert _with_stdin(io.StringIO("\ufeff{}")) == "{}"
    assert _with_stdin(io.StringIO("{}")) == "{}"


def test_bytes_that_are_not_utf8_raise_instead_of_being_guessed():
    """The bridges turn this into exit 2; nothing is decoded on a hunch."""
    stream = io.TextIOWrapper(io.BytesIO(b'{"a":"\xff"}'), encoding="cp1252")
    try:
        _with_stdin(stream)
    except UnicodeDecodeError:
        return
    raise AssertionError("invalid UTF-8 was accepted")
