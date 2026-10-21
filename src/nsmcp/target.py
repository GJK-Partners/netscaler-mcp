"""What a scan target is, and when it is valid.

The certificate rule from the phase-2 design lives HERE, in the constructor,
and not in the code that scans. An invalid target therefore cannot exist, and
the scan route does not need to check the rule again - nor can it bypass it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class TargetError(Exception):
    """The targets file is unsound. Deliberately no silent fallback."""


class CertAgreement(Enum):
    CHAIN = "keten"
    FINGERPRINT = "vingerafdruk"


# Stems that never belong in here. An MCP server has no operator watching
# along; a password in a configuration file is then not a convenience but a
# leak nobody notices. These are STEMS, not full key names - an exact match
# would miss common key names like 'clientSecret' and 'accessToken'. All
# lowercase AND without '-'/'_' - the comparison normalizes the key the same
# way (see _forbidden_keys), so 'api-key', 'x-api-key', 'api_key' and
# 'apiKey' all reduce to the same stem 'apikey' and only need to be listed
# here once.
FORBIDDEN_STEMS = (
    "passw",
    "pwd",
    "wachtwoord",
    "secret",
    "token",
    "apikey",
    "geheim",
    "passphrase",
    "privatekey",
    "authorization",
)


def _forbidden_keys(value) -> set[str]:
    """Searches the whole structure, not just the top layer.

    A secret one layer deeper is just as leaked as a secret at the top, and
    capital letters do not make it less of a secret. Iterates with an
    explicit stack instead of recursion: json.loads reads a deeply nested
    configuration without trouble, and this search must not then stumble
    over it with a raw RecursionError that leaks outside the TargetError
    contract.
    """
    found: set[str] = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, content in current.items():
                # Normalize instead of listing every spelling separately in
                # the stem list: strip '-' and '_' before the match, so
                # 'api-key', 'x-api-key' and 'api_key' all hit the stem
                # 'apikey'.
                normalized_key = str(key).lower().replace("-", "").replace("_", "")
                if any(stem in normalized_key for stem in FORBIDDEN_STEMS):
                    found.add(str(key))
                stack.append(content)
        elif isinstance(current, list):
            stack.extend(current)
    return found


def _build_object_pairs_hook(error_class):
    """Builds an object_pairs_hook for json.loads() that refuses a key that
    occurs twice at the SAME level, instead of - as json.loads() does by
    default - silently letting the last one win.

    Without this hook, configuration with 'profiel' twice (first shielded,
    then online) simply loads as 'online' - the fail-closed structure check
    afterwards never sees anything was wrong, because it only gets the
    already-won document. json.loads() calls object_pairs_hook for EVERY
    object it encounters, regardless of nesting depth - a single hook
    therefore also covers a duplicate one layer (or deeper) below the top
    level by itself, without separate recursion.

    `error_class` is the caller's own error class (ConfigError in start.py,
    TargetError here) - the same hook factory, two different contracts,
    exactly as _forbidden_keys() above is already reused by both files."""

    def hook(pairs):
        seen: dict = {}
        for key, value in pairs:
            if key in seen:
                raise error_class(
                    f"sleutel {key!r} komt dubbel voor op hetzelfde niveau in het "
                    "JSON-document; json.loads() zou de laatste stilzwijgend laten winnen, "
                    "en dat is precies het gat dat fail-closed laden moet dichten"
                )
            seen[key] = value
        return seen

    return hook


def _require(value, field: str) -> str:
    """Requires a real string. str(x) is a conversion, not a type gate: JSON
    null would otherwise become the text 'None' and end up on the command
    line of the collection script."""
    if not isinstance(value, str):
        raise ValueError(f"{field} moet tekst zijn, kreeg {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ValueError(f"{field} mag niet leeg zijn")
    return text


def _normalize_fingerprint(value) -> str:
    """Normalizes BEFORE the emptiness check, not after - otherwise a
    fingerprint that normalizes to nothing (':', ':::', '- -') survives the
    guard. Thumbprints are shown with spaces, colons or dashes, depending on
    the tool they come from.

    Like _require(), demands a real string (or None for 'no fingerprint') -
    str(x) is a conversion, not a type gate. This field IS the pin that the
    collection step puts on the command line of the collection script, so
    precisely here an int, bool, list or dict must not silently become
    'valid' text."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"vingerafdruk moet tekst zijn, kreeg {type(value).__name__}")
    text = value
    for separator in (":", "-"):
        text = text.replace(separator, "")
    return "".join(text.split()).upper()


@dataclass(frozen=True)
class Target:
    name: str
    address: str
    credential_target: str
    agreement: CertAgreement
    fingerprint: str | None = None
    # The SSH host key this target is expected to present, as a fingerprint.
    # A DIFFERENT key from `fingerprint` above: that one pins the MANAGEMENT
    # CERTIFICATE for the NITRO route, this one pins the SSH host key the
    # firmware-upgrade runner connects with. Optional here, because a
    # target that never runs a phase does not need one; `start.py` refuses
    # the combination "may run onderhoud_upgrade_fase, has no fingerprint".
    ssh_hostsleutel_vingerafdruk: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require(self.name, "naam"))
        object.__setattr__(self, "address", _require(self.address, "adres"))
        object.__setattr__(self, "credential_target", _require(self.credential_target, "credential_target"))
        if not isinstance(self.agreement, CertAgreement):
            # Like name/address/credential_target a real type gate, not just
            # an annotation: without this check e.g. agreement="vingerafdruk"
            # (the text, not an enum member) simply builds a Target, and
            # reads at every 'is' comparison as 'not FINGERPRINT' - a silent
            # fallback to chain validation on an object this design must not
            # allow.
            raise ValueError(f"afspraak moet een CertAgreement zijn, kreeg {type(self.agreement).__name__}")
        normalized = _normalize_fingerprint(self.fingerprint)
        if self.agreement is CertAgreement.FINGERPRINT:
            if not normalized:
                raise ValueError("afspraak 'vingerafdruk' zonder vingerafdruk is geen afspraak")
            object.__setattr__(self, "fingerprint", normalized)
        elif self.fingerprint is not None:
            # Fail-closed, not silently dropped: the field is filled in, so
            # the author meant something by it - even when it happens to
            # normalize to nothing (only ':' and '-' are stripped). It does
            # not belong with this agreement, so it is an error and not a
            # no-op.
            raise ValueError(
                f"afspraak '{self.agreement.value}' staat geen vingerafdruk toe: "
                "een vingerafdruk heeft daar geen betekenis"
            )
        # No else needed: if we get here, self.fingerprint is already None
        # (the elif above caught every non-None value), so there is nothing
        # left to normalize.
        #
        # ssh_hostsleutel_vingerafdruk carries no agreement of its own - it is
        # simply present or absent - so it gets the same normalize-then-check
        # discipline as `fingerprint` above, without the CertAgreement dance:
        # a value that is GIVEN but normalizes to nothing (only ':'/'-' and
        # whitespace) is fail-closed, not silently treated as "no key".
        raw_hostkey = self.ssh_hostsleutel_vingerafdruk
        if raw_hostkey is None:
            normalized_hostkey = None
        else:
            normalized_hostkey = _normalize_fingerprint(raw_hostkey)
            if not normalized_hostkey:
                raise ValueError("ssh_hostsleutel_vingerafdruk mag niet leeg zijn")
        object.__setattr__(self, "ssh_hostsleutel_vingerafdruk", normalized_hostkey)


def load_targets(path: Path) -> dict[str, Target]:
    """Reads the targets file. If it is absent, there are no targets - that
    is the service profile, not an error. If it is unsound, that IS an
    error."""
    if not path.exists():
        return {}
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TargetError(f"doelenbestand onleesbaar: {exc}") from None
    try:
        raw = json.loads(raw_text, object_pairs_hook=_build_object_pairs_hook(TargetError))
    except json.JSONDecodeError as exc:
        raise TargetError(f"doelenbestand onleesbaar: {exc}") from None
    except (RecursionError, MemoryError):
        # 1.0.2: too deep for the parser is unreadable, never a traceback.
        raise TargetError("doelenbestand onleesbaar: te diep genest") from None

    if not isinstance(raw, dict):
        raise TargetError(f"doelenbestand moet een object zijn met een sleutel 'doelen' (kreeg {type(raw).__name__})")

    secrets = _forbidden_keys(raw)
    if secrets:
        raise TargetError(
            f"doelenbestand draagt een geheim in de configuratie ({', '.join(sorted(secrets))}); "
            "alleen credentialTarget hoort hier te staan"
        )

    if "doelen" not in raw:
        raise TargetError("doelenbestand mist de sleutel 'doelen'")
    raw_targets = raw["doelen"]
    if not isinstance(raw_targets, list):
        raise TargetError(f"'doelen' moet een lijst zijn (kreeg {type(raw_targets).__name__})")

    targets: dict[str, Target] = {}
    for entry in raw_targets:
        if not isinstance(entry, dict):
            raise TargetError(f"elk doel moet een object zijn (kreeg {type(entry).__name__})")
        kind = str(entry.get("certificaat", "")).strip().lower()
        try:
            agreement = CertAgreement(kind)
        except ValueError:
            raise TargetError(f"onbekende certificaatafspraak '{kind}'; geldig is 'keten' of 'vingerafdruk'") from None
        try:
            target = Target(
                name=entry.get("naam", ""),
                address=entry.get("adres", ""),
                credential_target=entry.get("credentialTarget", ""),
                agreement=agreement,
                fingerprint=entry.get("vingerafdruk"),
                ssh_hostsleutel_vingerafdruk=entry.get("ssh_hostsleutel_vingerafdruk"),
            )
        except ValueError as exc:
            raise TargetError(f"ongeldig doel: {exc}") from None
        if target.name in targets:
            raise TargetError(f"doel '{target.name}' staat er twee keer in")
        targets[target.name] = target
    return targets
