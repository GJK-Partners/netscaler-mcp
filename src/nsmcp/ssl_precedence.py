"""A bound SSL profile overrides the vserver setting. One resolver, two users.

NSHC keeps exactly one implementation of this and says why
(backend/hiddenrules/NshcHiddenRules.ps1:29-35): scorecard control GJK-L1-010
uses the SAME resolver as the hidden rule NSHC-HR-SSL-005, because two
implementations could give two answers to one question inside one customer
report. This module is that single resolver on this side, used by
hidden_rules.py (NSHC-HR-SSL-005) and tls_baseline.py (A6).

Field lookup is CASE-INSENSITIVE on purpose: PowerShell property access is,
and the NITRO payload does not promise a casing. A resolver that is stricter
than the product it mirrors would report a difference that is not there.
"""

from __future__ import annotations

from dataclasses import dataclass

PROFILE_RESOURCE = "config/sslprofile"
VSERVER_RESOURCE = "config/sslvserver"


@dataclass(frozen=True)
class Resolved:
    vserver: str
    value: str
    source: str
    profile_bound: bool
    profile_read: bool
    profile_name: str


def field_text(row: dict, field: str) -> str:
    """The stripped text at `field`, case-insensitively, or "" ."""
    if not isinstance(row, dict):
        return ""
    lowered = field.lower()
    for key, raw in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            return raw.strip() if isinstance(raw, str) else ""
    return ""


def field_token(row: dict, field: str) -> str:
    """The value at `field` as PowerShell's own `[string]` cast would render
    it, case-insensitively, or "" .

    NSHC compares fields like `isdefault` and `builtin` after casting them
    through PowerShell's `[string]` operator: `[string]$true` -> "True",
    `[string]@('IMMUTABLE')` -> "IMMUTABLE" (PowerShell joins a multi-element
    array with a space, its default $OFS). The NITRO/JSON payload on this
    side carries the SAME two shapes - a JSON bool and a JSON array - and
    `field_text()` above deliberately returns "" for both (it feeds PATHS
    and EVIDENCE TEXT, where silently stringifying an arbitrary value would
    be a distortion the reader cannot see). This is the token-comparison
    counterpart: used ONLY to reproduce the PowerShell string form for an
    equality/contains check against a known vocabulary word, never to build
    displayed text. Do not widen `field_text` for this instead - that would
    blur the "never silently stringify a supplied value" rule it exists to
    enforce.

    MEASURED (2026-09-06, real fixture): every `config/rewritepolicy` row's
    `isdefault` is a JSON bool; every `config/responderpolicy` row's
    `builtin` is a JSON list (`['IMMUTABLE']`) or absent. `field_text` turns
    both into "", which is why NSHC-HR-RW-001 and NSHC-HR-RSP-001's isdefault
    /builtin guards were dead on real data before this helper existed.
    """
    if not isinstance(row, dict):
        return ""
    lowered = field.lower()
    for key, raw in row.items():
        if not (isinstance(key, str) and key.lower() == lowered):
            continue
        if isinstance(raw, bool):
            return "True" if raw else "False"
        if isinstance(raw, str):
            return raw.strip()
        if isinstance(raw, int):
            return str(raw)
        if isinstance(raw, (list, tuple)):
            return " ".join(str(item) for item in raw)
        return ""
    return ""


def profile_index(profiles: list[dict]) -> dict[str, dict]:
    """name (casefolded) -> profile row."""
    index: dict[str, dict] = {}
    for row in profiles:
        if not isinstance(row, dict):
            continue
        name = field_text(row, "name")
        if name:
            index[name.casefold()] = row
    return index


def resolve(vserver: dict, index: dict[str, dict], field: str) -> Resolved:
    """The EFFECTIVE value of `field` for this vserver.

    Three outcomes, and the middle one is the reason this exists:
    - no profile bound: the vserver's own value, source "vserver".
    - a profile bound AND read: the profile's value, source "profiel <naam>".
    - a profile bound and NOT in the read profile list: `profile_read` is
      False and `value` is "". The caller must then report NOT ESTABLISHED -
      never the vserver's own value, because the bound profile overrides it
      and we did not read it.
    """
    name = field_text(vserver, "vservername") or field_text(vserver, "name")
    bound = field_text(vserver, "sslprofile")
    if not bound:
        return Resolved(
            vserver=name,
            value=field_text(vserver, field),
            source="vserver",
            profile_bound=False,
            profile_read=False,
            profile_name="",
        )
    row = index.get(bound.casefold())
    if row is None:
        return Resolved(
            vserver=name,
            value="",
            source=f"profiel {bound}",
            profile_bound=True,
            profile_read=False,
            profile_name=bound,
        )
    return Resolved(
        vserver=name,
        value=field_text(row, field),
        source=f"profiel {bound}",
        profile_bound=True,
        profile_read=True,
        profile_name=bound,
    )
