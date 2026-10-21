"""The one way the two Python bridges (`upgrade_measure`, `upgrade_gate`)
read their request from stdin.

Why this is not a bare `sys.stdin.read()`: the caller is a Windows
PowerShell 5.1 script that pipes a JSON string into `python -m ...`.
Measured on a host whose console code page is 65001 (UTF-8; GitHub's
hosted Windows runner, and any workstation with the system-wide UTF-8
option switched on): Windows PowerShell 5.1 then writes the pipeline input
with a UTF-8 byte-order mark in front, even though `$OutputEncoding`
reports us-ascii. A text-mode read under the locale code page (cp1252)
turns that mark into three stray characters, and `json.loads` fails at
character 0 - the bridge answered "onleesbare invoer op stdin" to a
perfectly good request, and every phase closed as a read failure. On a
code page 850 host the same script sends no mark at all. PowerShell 7
never sends one.

So the bridges read BYTES and decode as `utf-8-sig`: a mark is stripped,
its absence is fine, plain ASCII (what `$OutputEncoding = us-ascii`
produces) is valid UTF-8, and anything that is not UTF-8 raises - which
`run()` in both bridges already turns into exit 2 without a traceback.
The fallback for a stdin without a byte buffer (a `StringIO` under test)
strips a leading mark from the text instead, so both shapes behave alike.
"""

from __future__ import annotations

import sys

_MARK = "\ufeff"


def read_stdin_text() -> str:
    """All of stdin as text, with a leading UTF-8 byte-order mark removed."""
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is None:
        return sys.stdin.read().lstrip(_MARK)
    return buffer.read().decode("utf-8-sig")
