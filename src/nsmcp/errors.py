"""Base class for every INTENDED tool error - a dependency-free leaf module.
`mask_error()` passes instances through unchanged; everything else is
replaced by the fixed message.
"""

from __future__ import annotations


class ToolError(Exception):
    """An INTENDED error the caller is allowed to see, e.g. an empty certnaam.

    Base class for every intended refusal/error in this product:
    `Refusal` (permissions.py), `IdentitySwitched` and `InvalidClientName`
    (mcp_server.py) are all subclasses. `mask_error()` in mcp_server.py
    passes instances of this class (and subclasses) through unchanged instead
    of replacing them with the generic "onverwachte fout" message - the text
    is meant to reach the caller, unlike an unexpected internal error.
    """
