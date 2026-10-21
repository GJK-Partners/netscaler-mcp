"""The decision point between "who is calling" and "the tool runs".

There is NO permission system in this product today. What does live here is
the moment where a decision CAN be made. The front door already establishes
the client identity and pins it per session; this is the point right after.

The difference is small in code and large in consequence: with this point in
place, setting up permissions later is a configuration job; without it, it
is a rebuild.

The seam carries three things: `decide(client_name, tool, arguments)`.
`arguments` is the mapping of parameter name to value of the called tool.
Without that third parameter a ROW-level rule ("this client may query target
`lab` but not `prod`", "may ask about certificate A but not B") would not
fit in this function: it would then have to change `_guarded`/`_guarded_async`
and all four call sites in mcp_server.py - exactly the rebuild this decision
point must prevent. Policy at the level of WHOLE tools ("may not use
`status_ververs`") was already possible with `tool` alone; policy on the
values INSIDE a tool needs `arguments`.

The decision and the action must see the same value - not "the raw value"
and not "the normalized value" as freely selectable alternatives, but ONE
canonical value that both use. mcp_server.py therefore normalizes ONCE,
before `decide()` is called, and passes that same normalized value to both
`arguments` here and to the tool itself (see `_decide()` in mcp_server.py).
A policy rule that simply matches on a value thus sees the form that
actually determines what happens, and can no longer be bypassed with
surrounding whitespace or another trivial spelling variant.
"""

from __future__ import annotations

from typing import Any

from nsmcp.errors import ToolError

__all__ = ["ToolError", "Refusal", "allow_all"]


class Refusal(ToolError):
    """This client may not use this tool.

    An intended outcome, not an internal error: the text may reach the
    caller. Subclass of ToolError, like IdentitySwitched and
    InvalidClientName in mcp_server.py: mask_error() passes ToolError
    (and subclasses) through unchanged instead of replacing them with the
    generic "onverwachte fout" message. _guarded()/_guarded_async() in
    mcp_server.py therefore simply raise this exception - there is no
    separate `except Refusal` block; it travels with the existing
    `except Exception -> mask_error()` handling, exactly like every other
    intended error in this product.
    """


def allow_all(client_name: str | None, tool: str, arguments: dict[str, Any]) -> None:
    """The default decision: everything is allowed.

    Replace this function (via the `decide` parameter of `build_server`) to
    turn it into a real decision. The front door does not need to change for
    that.

    `arguments` is the mapping of parameter name to the NORMALIZED value the
    tool itself also uses for its work - see the module docstring above for
    why that is the canonical form and not the raw, unnormalized input.
    """
    return None
