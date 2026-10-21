"""The production entry point: ONE configuration file, loaded fail-closed,
builds the server and starts it on stdio.

Three profiles, one build (see profile.py and the design, section "Drie
profielen"): the difference lies in what the configuration MAY contain, not
in three separate programs. Today that difference is minimal (YAGNI): the
dienst profile answers exclusively on a supplied export - scanning is out
of scope for that profile - so configuring `doelen`/`verzamelscript` for
dienst is not a no-op but an error, because the operator clearly meant
something by it that this profile cannot deliver. Afgeschermd and online
simply pass `doelen`/`verzamelscript` on to `build_server()`; what online
would have to do later (fetch knowledge itself) is deliberately not built -
that is a separate task, not a creeping addition here.

The same fail-closed discipline as target.py: every rejection gets its own,
recognizable Dutch message, never a silent fallback, and the same
forbidden-keys sweep (_forbidden_keys, reused here, not rebuilt) over the
WHOLE configuration document - not just over a targets list as in
target.py, but over every field an operator could put here. str(x) is a
conversion, not a type gate: every field is FIRST checked for its real type
before it is normalized (see _require_text below) - otherwise JSON null
silently becomes the text 'None' and ends up on a path or, worse, on the
command line of the collect script (the same pitfall
_require()/_normalize_fingerprint() in target.py already close).
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import warnings
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from nsmcp.backup import target_name_rules, valid_target_name
from nsmcp.code_channel import KINDS, MissingField, UnknownKind, presenter_for
from nsmcp.disclosure import Disclosure, load_disclosure
from nsmcp.handelen import (
    ARGUMENTS,
    DENIED_NAMES,
    DENIED_PREFIXES,
    OBJECTLESS_TOOLS,
    WRITE_TOOLS,
    Allowlist,
    MaintenanceConfig,
    _posh_ssh_wire_fingerprint,
)
from nsmcp.knowledge import KnowledgePin
from nsmcp.mcp_server import DEFAULT_CHAPTERS, build_server
from nsmcp.powershell import DEFAULT_EXECUTION_POLICY, EXECUTION_POLICIES, ScriptPolicy
from nsmcp.profile import Profile, load_profile
from nsmcp.retention import Retention
from nsmcp.target import Target, TargetError, _build_object_pairs_hook, _forbidden_keys, load_targets
from nsmcp.upgrade import is_safe_run_name, run_id
from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS

# `mcp==1.29.0` pulled in a pydantic_settings whose
# incomplete `lifespan` field definition printed an
# IncompleteFieldDefinitionWarning (plus its "warnings.warn(" source line)
# on stderr the moment FastMCP built its Settings object - older than this
# product, not something it can fix upstream, and pure noise on the
# five-minute demo path. `mcp==1.30.0` no longer emits it; the filter stays
# as a guard against a next release that does. Registered at import time,
# before build_server_from_config() ever constructs a FastMCP instance.
# NSMCP_DEBUG=1 restores it. mcp_server.py silences the matching FastMCP/mcp
# request-logging noise the same way.
if not os.environ.get("NSMCP_DEBUG"):
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        module=r"pydantic_settings\..*",
    )

_REQUIRED_FIELDS = {"profiel", "exportmap", "kennispad"}
_OPTIONAL_FIELDS = {
    "doelen",
    "verzamelscript",
    "openheid",
    "hoofdstukken",
    "handelen",
    "onderhoud",
    "bewaren",
    "kennispin",
    "scriptpin",
    "uitvoeringsbeleid",
}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS

# One source of truth: the chapter set lives in mcp_server.DEFAULT_CHAPTERS and
# is imported here instead of copied (it already includes `onderhoud`/`rapport`).
CHAPTERS = DEFAULT_CHAPTERS
_HANDELEN_FIELDS = {"schrijfscript", "fixturemap", "codekanaal", "toegestaan"}
# OPTIONAL. The upgrade runner's address guard needs a
# real, operator-owned address to compare against - and that address must
# never live as a literal in this repository's own source (it would become
# a pseudonymisation candidate there, silently). So it comes from here
# instead, validated below and handed to build_server() as forbidden_addresses.
_HANDELEN_OPTIONAL_FIELDS = {"verboden_adressen"}
_ONDERHOUD_FIELDS = {"runner", "ledgermap", "firmwaremap", "soak_uren", "ssh_gebruiker"}
# OPTIONAL - the action-log writer (`mcp_server._act()` via
# `nsmcp.upgrade.register_line()`) writes here when this key is
# configured, so a configured path lets R0's backup_register_gate leave
# `niet beoordeeld`; an unconfigured key keeps that gate at `niet
# beoordeeld`, the same treatment as `firmwaremap` (see _onderhoud_config
# below).
_ONDERHOUD_OPTIONAL_FIELDS = {"actieregister"}
# Which fields each channel kind carries next to `soort`. A new kind adds
# one row here and one branch in `code_channel.presenter_for()`.
_CHANNEL_FIELDS = {
    "venster": set(),
    "bestand": {"pad"},
    "sso": {"pad", "autoriteit", "wachttijd_s"},
}

_USAGE = "Gebruik: netscaler-mcp <pad-naar-config.json>"


class ConfigError(Exception):
    """The configuration is not sound. Deliberately no silent fallback."""


def _require_text(value, field: str) -> str:
    """Requires a real, non-empty string. str(x) is a conversion, not a
    type gate (see the module docstring): without this check JSON null
    becomes the text 'None', and a number or list also looks 'valid'
    through str() while the operator did not mean that."""
    if not isinstance(value, str):
        raise ConfigError(f"{field} moet tekst zijn, kreeg {type(value).__name__}")
    text = value.strip()
    if not text:
        raise ConfigError(f"{field} mag niet leeg zijn")
    return text


def _require_file(path: Path, what: str) -> None:
    """Refuses both a missing path and a DIRECTORY, each with its own
    message - is_file() instead of exists(): exists() is also true for a
    directory, and only afterwards would read_text() crash on an OSError
    (IsADirectoryError on Linux, PermissionError on Windows) that without
    this early check surfaces one step later, as a less clear error
    Used by load_config() and build_server_from_config() below, for all
    four file inputs that must be a REAL file here (the configuration
    file itself, handelen.schrijfscript, doelen, verzamelscript) - the
    knowledge path is deliberately NOT subjected to this: that field may
    legitimately be absent (a knowledge base is optional, see
    knowledge.py), so that check belongs there, not here.

    `path` !r-quoted in both messages: this is
    operator-controlled configuration text (the CLI argument itself, or
    handelen.schrijfscript/doelen/verzamelscript from the configuration
    document), never checked for control characters before this point -
    same reachable line-forgery as the eight places already closed
    (see test_all_reachable_line_forgeries_stay_one_line, which
    measures this end-to-end via run() and this fix
    closes)."""
    if path.is_dir():
        raise ConfigError(f"{what} is een map, geen bestand: {path!r}")
    if not path.is_file():
        raise ConfigError(f"{what} niet gevonden: {path!r}")


def load_config(path: Path) -> dict:
    """Reads and validates the configuration document STRUCTURALLY: does it
    exist, is it readable JSON, is the root an object, does it carry no
    secret, are all required fields present and no unknown fields. What
    does NOT happen here: checking field types (str vs int) or applying
    profile-specific rules - that is up to build_server_from_config(),
    which calls this function. The same layering as load_targets() in
    target.py: structure first, content second."""
    # 1.0.2: the configuration file itself goes through the same path
    # refusals, BEFORE anything opens it: a configuration on a share made
    # every relative path in it a network path.
    _refuse_remote_or_stream(str(path), "configuratiebestand")
    _refuse_where_it_leads(Path(path), "configuratiebestand")
    _require_file(path, "configuratiebestand")
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"configuratiebestand onleesbaar: {exc}") from None
    try:
        raw = json.loads(raw_text, object_pairs_hook=_build_object_pairs_hook(ConfigError))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"configuratiebestand is geen geldige JSON: {exc}") from None
    except (RecursionError, MemoryError):
        # 1.0.2: a document nested deeper than the parser can follow used to
        # end in a traceback instead of the promised "Fout: ..." line.
        raise ConfigError("configuratiebestand is te diep genest om te lezen") from None

    if not isinstance(raw, dict):
        raise ConfigError(f"configuratiebestand moet een object zijn (kreeg {type(raw).__name__})")

    secrets = _forbidden_keys(raw)
    if secrets:
        # !r-quoted per key, not plain-joined: `secrets`
        # holds the ORIGINAL top-level or nested JSON keys (target._forbidden_keys()
        # keeps `str(key)`, never a normalized form) - never checked for
        # control characters before this point. Same class as the `unknown`
        # sites below: a key carrying an embedded newline would otherwise
        # split the single `Fout: ...` line `run()` prints into two.
        raise ConfigError(
            "configuratie draagt een geheim in de configuratie "
            f"({', '.join(repr(v) for v in sorted(secrets))}); alleen de Credential "
            "Manager-targetnaam hoort hier te staan, nooit de waarde zelf"
        )

    missing = _REQUIRED_FIELDS - raw.keys()
    unknown = raw.keys() - _ALLOWED_FIELDS
    if missing and unknown:
        # Both in ONE message: a typo such as 'profil' instead of 'profiel'
        # would otherwise only yield "mist verplicht veld: profiel" and never
        # mention 'profil' - the operator would have to guess what is wrong.
        # With both fields named, the typo stands out immediately.
        #
        # `unknown` !r-quoted per key here and in the two standalone messages
        # below: these are top-level JSON keys the operator
        # typed, not yet checked for control characters - same reachable
        # line-forgery as the denylisted allowlist value above (see
        # test_a_denylisted_value_with_an_embedded_newline_stays_one_line).
        raise ConfigError(
            f"configuratie mist verplicht veld: {', '.join(sorted(missing))} "
            "(en bevat onbekend veld: "
            f"{', '.join(repr(v) for v in sorted(unknown))} - typefout?)"
        )
    if missing:
        raise ConfigError(f"configuratie mist verplicht veld: {', '.join(sorted(missing))}")
    if unknown:
        raise ConfigError(f"configuratie bevat onbekend veld: {', '.join(repr(v) for v in sorted(unknown))}")

    return raw


def _code_path_text(value) -> Path:
    """handelen.codekanaal.pad: the refusals of `_refuse_remote_or_stream`, then `_check_code_path`
    (which keeps requiring an absolute path - never resolved for it)."""
    text = _require_text(value, "handelen.codekanaal.pad")
    _refuse_remote_or_stream(text, "handelen.codekanaal.pad")
    _refuse_where_it_leads(Path(text), "handelen.codekanaal.pad")
    return Path(text)


def _code_channel(value, forbidden_dirs: list[Path]):
    """Validates `handelen.codekanaal` and hands the kind to the ONE seam.

    The shape is always an object with a `soort`, never a bare string, and
    that is a deliberate choice about the FUTURE: a later kind (a push to a
    phone, say) is then one extra kind next to the three of today instead of
    a second configuration shape - `sso` already proved the
    pattern. Which presenter a kind gets is not decided here but in
    `code_channel.presenter_for()` - one seam, so a new kind touches one
    function and no caller.

    What DOES belong here is the path discipline on the `bestand` kind, the
    same fail-closed discipline every other path in this file gets plus one
    rule of its own: the file may not sit in a directory the product itself
    reads or writes. Everything in the export map, the fixture map and the
    directories of the knowledge, targets and collect files can end up in an
    answer or in a scrub sweep; a live confirmation code has no business
    anywhere near that. A relative path is refused outright - the server's
    working directory is whatever client spawned it happened to have, so a
    relative path names a different file per client. That is a statement
    about this configuration as a whole, which is why it lives here and not
    in the channel module.
    """
    if not isinstance(value, dict):
        raise ConfigError('handelen.codekanaal moet een object met een soort zijn, bijvoorbeeld {"soort": "venster"}')
    if "soort" not in value:
        raise ConfigError(f"handelen.codekanaal mist het veld soort; toegestaan: {', '.join(KINDS)}")
    kind = _require_text(value["soort"], "handelen.codekanaal.soort")
    if kind not in KINDS:
        # Before the field checks below: on an unknown kind those would report
        # a field name while the real problem is the kind itself.
        #
        # !r-quoted: `kind` is here still the operator's OWN
        # `soort` text, not yet checked against KINDS and therefore not yet
        # checked for control characters either - a value carrying an
        # embedded newline would otherwise split the single `Fout: ...` line
        # `run()` prints into two (same class as
        # test_a_denylisted_value_with_an_embedded_newline_stays_one_line).
        raise ConfigError(f"onbekende soort codekanaal: {kind!r}; toegestaan: {', '.join(KINDS)}")
    fields = {name: waarde for name, waarde in value.items() if name != "soort"}
    if kind == "bestand":
        if "pad" not in fields:
            raise ConfigError(
                "handelen.codekanaal van soort bestand mist het veld pad (een absoluut pad naar het codebestand)"
            )
        fields["pad"] = _check_code_path(_code_path_text(fields["pad"]), forbidden_dirs)
    if kind == "sso":
        ontbreekt = [v for v in ("pad", "autoriteit", "wachttijd_s") if v not in fields]
        if ontbreekt:
            raise ConfigError(
                "handelen.codekanaal van soort sso mist het veld "
                f"{', '.join(sorted(ontbreekt))}; pad wijst naar de presenter, autoriteit is de "
                "https-url waar de goedkeuring vandaan komt en wachttijd_s is het aantal seconden "
                "dat het product op aflevering wacht"
            )
        fields["pad"] = _check_code_path(_code_path_text(fields["pad"]), forbidden_dirs)
        # `_check_code_path` was built for
        # the `bestand` kind's code FILE, a path where nothing needs to
        # exist yet - the product writes it. The `sso` presenter is the
        # opposite: an executable dependency, exactly like `schrijfscript`
        # and `fixturemap` below, both of which refuse to start when they
        # do not exist. Without this, a typo in `pad` starts the server
        # happily and every write in that session dies at the channel with
        # "de presenter kon niet gestart worden" - after the code was
        # already issued and burnt.
        _require_file(fields["pad"], "handelen.codekanaal.pad")
        fields["autoriteit"] = _require_text(fields["autoriteit"], "handelen.codekanaal.autoriteit")
        if not fields["autoriteit"].lower().startswith("https://"):
            raise ConfigError(
                "handelen.codekanaal.autoriteit moet een https-url zijn: een goedkeuring over http is geen goedkeuring"
            )
        # `isinstance(fields["wachttijd_s"], int) and not isinstance(..., bool)`
        # `bool` is an `int` subclass in
        # Python, so a bare `isinstance(x, int)` lets `True` through as 1 -
        # `"wachttijd_s": true` would silently become a one-second wait
        # instead of the configuration error it is. This file elsewhere
        # explicitly refuses conversion-as-validation (`_require_text`'s own
        # docstring); a type gate that admits `bool` where an `int` was
        # asked for is the same mistake.
        wachttijd = fields["wachttijd_s"]
        if not isinstance(wachttijd, int) or isinstance(wachttijd, bool) or wachttijd <= 0:
            raise ConfigError("handelen.codekanaal.wachttijd_s moet een positief geheel getal zijn")
    # `kind` is a known member of KINDS from here on (the check above already
    # refused anything else) - safe to interpolate bare. `unknown`, the field
    # NAMES under this codekanaal object, is not: !r-quoted per field,
    # same reachable line-forgery as `unknown` in
    # load_config() above.
    unknown = set(fields) - _CHANNEL_FIELDS.get(kind, set())
    if unknown:
        raise ConfigError(
            f"onbekend veld in handelen.codekanaal van soort {kind}: {', '.join(repr(v) for v in sorted(unknown))}"
        )
    try:
        return presenter_for(kind, fields)
    except UnknownKind:
        # Unreachable through the gate above; kept as a backstop so a kind that
        # is added to KINDS but not to presenter_for() fails loudly and closed
        # instead of building a server whose writing tools cannot work. `kind`
        # is bare here on purpose, not !r-quoted like the reachable check
        # above: by this point it is guaranteed a member of KINDS (a
        # fixed, safe set of names), never arbitrary operator text.
        raise ConfigError(f"onbekende soort codekanaal: {kind}; toegestaan: {', '.join(KINDS)}") from None
    except MissingField as exc:
        # `kind` bare here too, for the same reason as the UnknownKind branch
        # just above: this point is only reached once `kind in KINDS`.
        raise ConfigError(f"handelen.codekanaal van soort {kind} mist het veld {exc}") from None


def _onderhoud_path(value, field: str, base: Path | None) -> Path:
    """`_config_path` when the caller knows the configuration's directory;
    a direct caller without it (a test) keeps the old reading, with the
    refusals of `_refuse_remote_or_stream` all the same."""
    if base is not None:
        return _config_path(value, field, base)
    text = _require_text(value, field)
    _refuse_remote_or_stream(text, field)
    _refuse_where_it_leads(Path(text), field)
    return Path(text)


def _onderhoud_config(value, *, handelen_configured: bool, base: Path | None = None) -> MaintenanceConfig:
    """Validates `onderhoud` STRUCTURALLY: the five required fields, the
    soak-hours floor, that `runner` is a real file and `ledgermap` a real
    directory, and that `handelen` is configured at all - a phase is a
    WRITING handeling, so `onderhoud` without `handelen` cannot ever run
    one. Five of the task's seven pinned start errors live here, in this
    order. `firmwaremap` gets no existence check (unlike `runner`/
    `ledgermap`): the firmware bundle for a maintenance window may
    legitimately arrive AFTER the server started, and the seven-error
    table names no such check - `handelen.py._firmware_target_build()` fails
    that honestly, at call time, when the bundle is missing.

    The sixth error (the per-target hostkey check) is NOT here: it needs
    `toegestaan` AND the target file both read, which this function has
    neither of - `build_server_from_config()` runs it itself once both
    exist, via `_require_upgrade_hostkeys()` below. The seventh ("no error
    at all") is not a check but the ABSENCE of one: a target that may not
    run the tool simply does not get it registered (`mcp_server.py`).
    """
    if not isinstance(value, dict):
        raise ConfigError("onderhoud moet een object zijn")
    missing = _ONDERHOUD_FIELDS - value.keys()
    if missing:
        raise ConfigError(f"onderhoud mist veld: {', '.join(sorted(missing))}")
    unknown = value.keys() - _ONDERHOUD_FIELDS - _ONDERHOUD_OPTIONAL_FIELDS
    if unknown:
        raise ConfigError(f"onbekend veld in onderhoud: {', '.join(sorted(unknown))}")
    soak_uren = value["soak_uren"]
    # bool is an int subclass (the same pitfall handelen.codekanaal.wachttijd_s
    # already guards against, above): a bare isinstance(x, int) would let
    # `"soak_uren": true` through as 1.
    if not isinstance(soak_uren, int) or isinstance(soak_uren, bool) or soak_uren < MINIMUM_SOAK_HOURS:
        raise ConfigError(
            f"onderhoud.soak_uren moet minimaal {MINIMUM_SOAK_HOURS} zijn; een werkdag is in dit "
            "product 24 uur wandkloktijd, en juist de nacht is het venster waarin een stille "
            "regressie zichtbaar wordt"
        )
    runner = _onderhoud_path(value["runner"], "onderhoud.runner", base)
    if not runner.is_file():
        raise ConfigError(f"onderhoud.runner is geen bestand: {runner}")
    ledgermap = _onderhoud_path(value["ledgermap"], "onderhoud.ledgermap", base)
    if not ledgermap.is_dir():
        raise ConfigError(f"onderhoud.ledgermap is geen map: {ledgermap}")
    firmwaremap = _onderhoud_path(value["firmwaremap"], "onderhoud.firmwaremap", base)
    ssh_gebruiker = _require_text(value["ssh_gebruiker"], "onderhoud.ssh_gebruiker")
    # Same treatment as `firmwaremap` above - no
    # existence check: the register may not exist yet until the first write
    # happens. `nsmcp.upgrade.backup_register_gate` and friends already
    # degrade an unreadable/absent path to `niet beoordeeld` rather than
    # `open`.
    actieregister = None
    if "actieregister" in value:
        actieregister = _onderhoud_path(value["actieregister"], "onderhoud.actieregister", base)
    if not handelen_configured:
        raise ConfigError("onderhoud vereist de sectie handelen; een fase is een schrijvende handeling")
    return MaintenanceConfig(
        runner=runner,
        ledgermap=ledgermap,
        firmwaremap=firmwaremap,
        soak_uren=soak_uren,
        ssh_gebruiker=ssh_gebruiker,
        actieregister=actieregister,
    )


def _require_safe_upgrade_target_names(allowlist: Allowlist) -> None:
    """A target name reaches
    `nsmcp.upgrade.run_id(doelnaam, ...)` (`mcp_server.py`'s R0 branch of
    `_act()`) UNCHECKED - `_target_for()` only checks that the caller's
    `doel` is one of the CONFIGURED names, never that the name's own
    characters are safe to become part of a run id. A comment at that call
    site used to claim this could not happen ("`doelnaam` is already
    `validate()`-checked appliance-object grammar") - false: `validate()`
    checks NITRO object arguments (a certnaam, say), never the target name
    itself, which is whatever key an operator wrote in `handelen.
    toegestaan`. A name `run_id()` cannot turn into a safe run name (a
    space, a colon, anything outside `is_safe_run_name()`'s path-segment
    grammar) then makes R0 refuse PERMANENTLY on that target with "de
    run-naam voor deze fase is geen veilig pad-segment" - fail-closed, but
    a misleading diagnosis of a `run` the operator never supplied. Caught
    HERE instead, at configuration-read time, next to
    `_require_upgrade_hostkeys` (same scope: only the targets the
    allowlist actually grants `onderhoud_upgrade_fase` to), with a message
    that names the real cause.

    The clock passed to `run_id()` is fixed and arbitrary: only the
    CHARACTER shape of `doelnaam` is being judged here (the timestamp
    prefix `run_id()` writes is always `[A-Za-z0-9]`, so it never affects
    whether the result is safe), not any particular moment."""
    proefmoment = datetime(2000, 1, 1, tzinfo=UTC)
    for naam in allowlist.targets():
        if not allowlist.allows(naam, "onderhoud_upgrade_fase"):
            continue
        if not is_safe_run_name(run_id(naam, proefmoment)):
            raise ConfigError(
                f"doel {naam} mag onderhoud_upgrade_fase uitvoeren maar de doelnaam is geen "
                "veilig pad-segment; onderhoud_upgrade_fase vormt uit deze doelnaam de eerste "
                "run-naam (alleen letters, cijfers, punt, liggend streepje en koppelteken)"
            )


def _require_upgrade_hostkeys(allowlist: Allowlist, targets: dict) -> None:
    """The sixth of the task's seven pinned start errors - checked LAST,
    because it needs `toegestaan` (the allowlist) and the target file BOTH
    read, and runs over EVERY target the allowlist grants
    `onderhoud_upgrade_fase` to. A name the target file does not carry at
    all gets the SAME sentence as one that carries no
    `ssh_hostsleutel_vingerafdruk`: both cases mean this server has no
    pinned key for a target the allowlist says may run a phase."""
    for naam in allowlist.targets():
        if not allowlist.allows(naam, "onderhoud_upgrade_fase"):
            continue
        doel = targets.get(naam)
        if doel is None or not doel.ssh_hostsleutel_vingerafdruk:
            raise ConfigError(
                f"doel {naam} mag onderhoud_upgrade_fase uitvoeren maar draagt geen "
                "ssh_hostsleutel_vingerafdruk; de runner pint de hostsleutel en accepteert er "
                "nooit een"
            )


def _require_hex_upgrade_hostkeys(allowlist: Allowlist, targets: dict) -> None:
    """`target._normalize_fingerprint`
    strips `:`/`-` and uppercases but never validates that what is left is
    HEX. `ssh-keygen -l`'s own DEFAULT output shape -
    `SHA256:abcXYZ/+q` - normalizes to `SHA256ABCXYZ/+Q`, and
    `_posh_ssh_wire_fingerprint()` (`handelen.py`, called from
    `build_upgrade_arguments()`) then raises a bare `ValueError` trying to
    `bytes.fromhex()` that. A bare `ValueError` is not an `ActionError`, so
    it escapes `build_upgrade_arguments()`'s own handler in
    `mcp_server.py` and is masked into the generic "Onverwachte fout ...
    details zijn niet bewaard" - every phase call on that target fails
    with zero diagnosis of why.

    Caught HERE instead, the same scope and moment as
    `_require_upgrade_hostkeys`/`_require_ip_upgrade_targets` above/below
    (only the targets the allowlist actually grants
    `onderhoud_upgrade_fase` to, and only once a pin is confirmed present -
    `_require_upgrade_hostkeys` already refuses a MISSING pin, so this
    skips that case rather than repeating it): the EXACT SAME conversion
    `build_upgrade_arguments()` would otherwise crash on, reused rather
    than reimplemented as a second hex check that could drift from it, run
    once at start-time where a `ValueError` becomes an honest `ConfigError`
    naming the expected form."""
    for naam in allowlist.targets():
        if not allowlist.allows(naam, "onderhoud_upgrade_fase"):
            continue
        doel = targets.get(naam)
        if doel is None or not doel.ssh_hostsleutel_vingerafdruk:
            continue
        try:
            _posh_ssh_wire_fingerprint(doel.ssh_hostsleutel_vingerafdruk)
        except ValueError as exc:
            raise ConfigError(
                f"doel {naam} mag onderhoud_upgrade_fase uitvoeren maar "
                f"ssh_hostsleutel_vingerafdruk is geen geldige hex-vingerafdruk ({exc}); "
                "verwachte vorm: hex-tekens, twee per byte, met of zonder ':'/'-' als "
                "scheidingsteken (het formaat van 'ssh-keygen -l -E md5', niet het "
                "SHA256:<base64>-formaat dat 'ssh-keygen -l' zonder -E toont)"
            ) from None


_IPV4_SHAPE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _require_ip_upgrade_targets(allowlist: Allowlist, targets: dict) -> None:
    """`secondary_gate()` (`nsmcp.upgrade`)
    compares Node ID 0's own `IP:` field against a target's configured
    `adres` as a LITERAL STRING - deliberately (its own docstring: the
    judging half stays pure, no DNS lookup inside it). For a target
    configured with a HOSTNAME rather than the NSIP that field always
    carries, that comparison can never match, so `doel is secondary` reads
    `niet beoordeeld` on EVERY R1 and R5 call - and since that gate sits in
    `REQUIRED_GATES` for both, R1 and R5 can then never close `geslaagd` on
    that target. Fail-closed, but silent and undiagnosable from the
    operator's side: nothing refused at configuration-read time, and
    `HANDLEIDING.md` used to show a hostname in its own example.

    Caught HERE instead, the same scope and the same moment as
    `_require_upgrade_hostkeys` (only the targets the allowlist actually
    grants `onderhoud_upgrade_fase` to): `adres` must be a literal IPv4
    address, checked by SHAPE only (an octet above 255 still matches - the
    same conservative, DNS-free spirit `secondary_gate`'s own
    `_IPV4_SHAPE` uses), not resolved or otherwise interpreted. A target
    that never runs a phase is untouched - a hostname `adres` is completely
    normal there."""
    for naam in allowlist.targets():
        if not allowlist.allows(naam, "onderhoud_upgrade_fase"):
            continue
        doel = targets.get(naam)
        if doel is None:
            continue
        if not _IPV4_SHAPE.match(doel.address):
            raise ConfigError(
                f"doel {naam} mag onderhoud_upgrade_fase uitvoeren maar adres "
                f"{doel.address!r} is geen letterlijk IPv4-adres; secondary_gate vergelijkt "
                "het IP van Node ID 0 als tekst en doet geen naamresolutie, dus R1 en R5 "
                "zouden op dit doel nooit kunnen sluiten - configureer hier het NSIP"
            )


_DIGEST_FORM = re.compile(r"[0-9a-f]{64}")


def _require_printable_targets(targets: dict) -> None:
    """Refuses a target whose name or address carries a control character.

    Both travel into every write script as `-Doel` and `-Adres`, and the
    scripts print them in the `[TARGET]` line the confirmation code binds
    to. `target.load_targets()` strips only the ends, so a CR, LF or tab
    INSIDE the value survived: a name `lab\\n[ACTIEID] ...` printed a marker
    line of its own. `str.isprintable()` also refuses the other line
    separators Python itself splits on (NEL, U+2028, U+2029). Every target in
    the file, not only the ones a tool may write to: the collection script
    gets the address on its command line too. The value is !r-quoted, so the
    message itself stays one line."""
    for doel in targets.values():
        for veld, waarde in (("naam", doel.name), ("adres", doel.address)):
            if not waarde.isprintable():
                raise ConfigError(
                    f"doelenbestand: {veld} {waarde!r} draagt een stuurteken (regeleinde, tab of een ander "
                    "niet-afdrukbaar teken); deze waarde komt in het etiket waaraan een bevestigingscode hangt"
                )


def _address_key(adres: str) -> str:
    """The spelling two target addresses are compared in: lower case, every
    whitespace character removed. Text only - never resolved (the reading
    tools open no socket, and neither does the start), so a host name and an
    IP address for one appliance stay two addresses."""
    return "".join(adres.split()).lower()


def _require_one_target_per_address(targets: dict) -> None:
    """Refuses a targets file in which two targets carry the same address.

    Everything that keeps a second writer off an appliance holds a target by
    its NAME: the open-phase refusal and the register of undecided starts
    (both on `upgrade_gate._normalised_target()`, so capitalisation and the
    domain part of an FQDN do not make another target), and the phase
    runner's own check on `-Doel`. Measured: a second configured name with
    another first label for the same address (`doos-b` next to
    `netscaler-02`, both `10.0.0.2`) got past all three - a backup on it was
    proposed and really run while a phase start on the other name was
    undecided, and again once that phase was open. Refused here instead, for
    every target in the file (not only the ones a tool may write to: the
    file is the one place that says which appliance a name means), with both
    names in the message. Compared on `_address_key()`, so only a spelling
    of the same TEXT is caught; one appliance under a host name and under
    its IP address is not, and the documentation says so."""
    seen: dict[str, Target] = {}
    for doel in targets.values():
        key = _address_key(doel.address)
        eerder = seen.get(key)
        if eerder is None:
            seen[key] = doel
            continue
        adressen = repr(eerder.address) if eerder.address == doel.address else f"{eerder.address!r} en {doel.address!r}"
        raise ConfigError(
            f"doelenbestand: de doelen {eerder.name!r} en {doel.name!r} hebben hetzelfde adres ({adressen}); "
            "een appliance staat met precies een adres in het doelenbestand - de weigering voor een openstaande "
            "fase, de blokkade van een onbesliste start en de faserunner houden een doel bij zijn naam vast, "
            "dus twee namen voor een adres zouden elkaar niet tegenhouden"
        )


def _kennispin(value) -> KnowledgePin:
    """Reads `kennispin` into a `KnowledgePin`, or refuses: exactly `versie`
    (the package's own version text) and `digest` (the sha256 of its
    canonical content, as `python -m nsmcp.knowledge --digest <pad>` prints
    it). Strict at startup, the same discipline as every other section: a
    pin that cannot match anything would refuse every package later, far
    from the line that caused it. Neither value is repeated in a refusal -
    the digest is the one value a forger would aim at."""
    if not isinstance(value, dict):
        raise ConfigError("kennispin moet een object zijn met versie en digest")
    if value.keys() != {"versie", "digest"}:
        raise ConfigError("kennispin draagt precies de velden versie en digest")
    version = _require_text(value["versie"], "kennispin.versie")
    digest = value["digest"]
    if not isinstance(digest, str) or _DIGEST_FORM.fullmatch(digest.strip().lower()) is None:
        raise ConfigError(
            "kennispin.digest moet een sha256 van 64 hexadecimale tekens zijn;"
            " bereken hem met: python -m nsmcp.knowledge --digest <kennispad>"
        )
    return KnowledgePin(version=version, digest=digest.strip().lower())


def _verboden_adressen(value) -> tuple[str, ...]:
    """Reads `handelen.verboden_adressen` into a tuple of address strings, or
    refuses. The upgrade runner's address guard needs
    its real comparison value from the OPERATOR's own configuration, never
    from a literal in this repository's source (see
    `build_upgrade_arguments()` in handelen.py and `-VerbodenAdressen` in
    `scripts/Invoke-GjkUpgradeFase.ps1`). Strict at startup, the same
    discipline as `_allowlist()` right below: a list, and every element a
    non-empty string without whitespace (the runner's own normalisation
    trims/lowercases/strips a port suffix, so an address with embedded
    whitespace could never match anything there anyway - reject it here
    instead of silently carrying a value that can never fire)."""
    if not isinstance(value, list):
        raise ConfigError("handelen.verboden_adressen moet een lijst teksten zijn")
    adressen: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or any(ch.isspace() for ch in item):
            raise ConfigError(f"handelen.verboden_adressen: {item!r} moet een niet-lege tekst zijn zonder witruimte")
        adressen.append(item)
    return tuple(adressen)


def _allowlist(value) -> Allowlist:
    """Reads `handelen.toegestaan` into an `Allowlist`, or refuses.

    Strict at STARTUP on purpose. Everything this checks would otherwise
    surface as a refusal in the middle of a proposal, at the moment an
    operator least wants to debug a configuration file - and one of the
    checks (a denylist name inside the allowlist) is a security boundary the
    operator must be TOLD about, not a refusal that quietly happens later.

    That includes the doelnaam GRAMMAR: before
    this check existed, this function accepted any non-empty stripped string
    as a target name, and `backup.backup_name()` then refused exactly the
    ones this function let through - "lab noord", "../x" - with a
    `ValueError` that `mcp_server._act()` does not catch, so the server
    STARTED fine and every backup proposal on that target ended, uncaught,
    as the generic "Onverwachte fout ... De details zijn niet bewaard".
    That is precisely the class of bug this function exists to prevent, so
    the doelnaam is validated here against `nsmcp.backup.valid_target_name`
    - the SAME predicate `backup_name()` itself refuses by, imported rather
    than copied so the two can never drift apart again. That includes the
    LENGTH bound: `valid_target_name()` also
    refuses a doelnaam longer than `backup.MAX_TARGET_LENGTH`, so a target
    the formed backup name could not carry (it would no longer satisfy
    `handelen._NAME`'s 63-character ceiling) is refused HERE, at startup,
    not mid-proposal.
    """
    if not isinstance(value, dict):
        raise ConfigError("handelen.toegestaan moet een object zijn met per doelnaam een object van handelingen")
    per_target: dict = {}
    for target_name, section in value.items():
        naam = _require_text(target_name, "handelen.toegestaan (doelnaam)")
        if not valid_target_name(naam):
            # !r-quoted, not plain-quoted: `naam` is the operator's OWN
            # configuration text (never appliance-controlled), but it has
            # not yet been checked for control characters at this point -
            # echoing it unquoted would let a doelnaam carrying a newline
            # forge an extra-looking line in this message (same class of
            # issue measured in backup.py: a trailing "\n" that a plain
            # echo would not visibly set apart).
            raise ConfigError(
                f"handelen.toegestaan: doelnaam {naam!r} voldoet niet aan de eisen "
                f"({target_name_rules()}); deze naam wordt straks onderdeel van een "
                "appliance-side objectnaam (bijvoorbeeld bij een backup)"
            )
        if naam in per_target:
            # _require_text strips, so "lab" and " lab" are one key here while
            # JSON saw two. Without this the second section would silently
            # overwrite the first - a whole allowlist section gone, unreported.
            raise ConfigError(
                f"handelen.toegestaan: doelnaam {naam!r} staat er twee keer in (namen worden "
                "van omringende spaties ontdaan); geef elk doel een eigen naam"
            )
        if not isinstance(section, dict):
            raise ConfigError(
                f"handelen.toegestaan.{naam} moet een object zijn van handeling naar toegestane "
                "waarden, of naar true/false"
            )
        entries: dict = {}
        for tool, entry in section.items():
            if tool not in WRITE_TOOLS:
                # !r-quoted (same class of issue as the
                # doelnaam message above): `tool` is here still an arbitrary
                # dict key from the configuration - it is PRECISELY this
                # check that establishes whether it is a known tool name at
                # all, so it has not yet been checked for control characters
                # at this point.
                raise ConfigError(
                    f"handelen.toegestaan.{naam}: {tool!r} is geen schrijvend gereedschap; "
                    f"toegestaan: {', '.join(WRITE_TOOLS)}"
                )
            if isinstance(entry, bool):
                if tool not in OBJECTLESS_TOOLS:
                    raise ConfigError(
                        f"handelen.toegestaan.{naam}.{tool}: true/false mag alleen bij een "
                        f"handeling die zijn object zelf vormt; {tool} vormt zijn object niet "
                        "zelf, zet per argument de toegestane waarden"
                    )
                entries[tool] = entry
                continue
            if tool in OBJECTLESS_TOOLS:
                raise ConfigError(
                    f"handelen.toegestaan.{naam}.{tool}: deze handeling vormt zijn object zelf; zet true of false"
                )
            if not isinstance(entry, dict):
                raise ConfigError(
                    f"handelen.toegestaan.{naam}.{tool} moet een object zijn van argument naar "
                    "een lijst toegestane waarden"
                )
            unknown_args = entry.keys() - set(ARGUMENTS[tool])
            if unknown_args:
                # !r-quoted per argument name: `unknown_args`
                # is `entry.keys()`, argument names the operator typed under
                # this tool - not yet checked for control characters.
                # `ARGUMENTS[tool]` stays bare: a fixed, known-safe tuple.
                raise ConfigError(
                    f"handelen.toegestaan.{naam}.{tool}: onbekend argument "
                    f"{', '.join(repr(v) for v in sorted(unknown_args))}; "
                    f"toegestaan: {', '.join(ARGUMENTS[tool])}"
                )
            # EXACTLY the arguments of this tool, all of them. validate()
            # looks every argument up, so a missing key becomes an empty tuple
            # there and refuses every call - with an empty allowed-values list
            # behind the refusal. That is precisely the mid-proposal debugging
            # this function exists to prevent. An EMPTY LIST per argument does
            # stay valid: absent, false and an empty list all mean "not
            # allowed" (see Allowlist), and an operator who removes the last
            # value must not be forced to remove the key as well.
            missing_args = set(ARGUMENTS[tool]) - entry.keys()
            if missing_args:
                raise ConfigError(
                    f"handelen.toegestaan.{naam}.{tool}: ontbrekend argument "
                    f"{', '.join(sorted(missing_args))}; vereist: {', '.join(ARGUMENTS[tool])} - "
                    "zonder waarden voor elk argument weigert deze handeling elke aanroep"
                )
            per_tool: dict = {}
            for field, values in entry.items():
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    raise ConfigError(f"handelen.toegestaan.{naam}.{tool}.{field} moet een lijst teksten zijn")
                for candidate in values:
                    if candidate.startswith(DENIED_PREFIXES) or candidate in DENIED_NAMES:
                        # !r-quoted, not plain-quoted (hardening):
                        # `candidate` is an allowlist VALUE from
                        # the operator's own configuration, never checked for
                        # control characters before this point. Measured: a
                        # value carrying an embedded newline (reachable via
                        # this DENIED_PREFIXES branch, e.g. "nshttps-\nFout:
                        # niets aan de hand") turned the single `Fout: ...`
                        # line `run()` prints into two, and the second line
                        # read as its own, forged "Fout:" line. `!r` escapes
                        # the newline instead of emitting it, so the output
                        # stays one line - see
                        # test_a_denylisted_value_with_an_embedded_newline_stays_one_line.
                        raise ConfigError(
                            f"handelen.toegestaan.{naam}.{tool}.{field}: {candidate!r} staat op "
                            "de ingebouwde denylist en kan door een allowlist nooit vrijgegeven "
                            "worden"
                        )
                per_tool[field] = tuple(values)
            entries[tool] = per_tool
        per_target[naam] = entries
    return Allowlist(per_target=per_target)


_EXTENDED_PREFIXES = ("\\\\?\\", "\\\\.\\")


def _without_extended_prefix(text: str) -> str:
    """`text` without the Windows extended (`\\\\?\\`) or device (`\\\\.\\`)
    prefix, when what follows is a drive letter or `UNC\\<host>\\<share>`:
    `\\\\?\\C:\\x` becomes `C:\\x`, `\\\\?\\UNC\\host\\share\\x` becomes
    `\\\\host\\share\\x`. Any other prefixed form (a volume GUID, a device
    name) has no drive spelling to peel down to and is returned unchanged -
    `_lies_within` still compares it by identity."""
    for prefix in _EXTENDED_PREFIXES:
        if not text.startswith(prefix):
            continue
        rest = text[len(prefix) :]
        if rest[:4].upper() == "UNC\\":
            return "\\\\" + rest[4:]
        if len(rest) >= 2 and rest[1] == ":" and rest[0].isascii() and rest[0].isalpha():
            # A bare `C:` would read as "the current directory on C:"; the
            # prefixed form names the volume, so it is peeled to its root.
            return rest if len(rest) > 2 else rest + "\\"
    return text


# 1.0.2. Where a configured path may point. Measured on 1.0.0: a
# relative path followed the working directory of the MCP host (one config,
# two exports, depending on who started it - and the client configuration
# from the manual did not start at all); a UNC export map turned every
# reading tool into an SMB client; `kennis.json:zijstroom` (an alternate data
# stream) passed `is_file()`. Now: a relative path is resolved against the
# directory of the configuration file, one that still depends on the current
# drive or root (`C:x`, `\x`) is refused, and so is every network or device
# spelling, a colon after the drive letter and a component that ends in a dot
# or a space (Windows drops those, so the name read is not the name written).
_LOCAL_DEVICE_DRIVE = re.compile(r"^\\\\[?.]\\[A-Za-z]:(\\|$)")
_LOCAL_VOLUME_GUID = re.compile(r"^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}(\\|$)")


def _refuse_remote_or_stream(text: str, field: str) -> None:
    """Refuses the spellings described above in `text` (operator text, `!r`-quoted)."""
    if os.name != "nt":
        return
    spelled = text.replace("/", "\\")
    rest = spelled
    if spelled.startswith("\\\\"):
        if _LOCAL_DEVICE_DRIVE.match(spelled):
            rest = spelled[4:]
        elif _LOCAL_VOLUME_GUID.match(spelled):
            rest = spelled[_LOCAL_VOLUME_GUID.match(spelled).end() :]
        else:
            raise ConfigError(
                f"{field} is een netwerk- of apparaatpad; deze versie leest alleen van een lokale schijf"
                f" (geen \\\\server\\share, geen \\\\?\\UNC\\): {text!r}"
            )
    if len(rest) >= 2 and rest[1] == ":" and rest[0].isascii() and rest[0].isalpha():
        rest = rest[2:]
    if ":" in rest:
        raise ConfigError(
            f"{field} draagt een dubbele punt na de schijfletter (een alternatieve gegevensstroom of geen geldig"
            f" pad): {text!r}"
        )
    for part in rest.split("\\"):
        if part not in ("", ".", "..") and part[-1] in (".", " "):
            raise ConfigError(
                f"{field} heeft een padonderdeel dat op een punt of spatie eindigt; Windows laat die weg, dus"
                f" de naam die gelezen wordt is niet de naam die er staat: {text!r}"
            )


# 1.0.2, second round. The refusals above read the SPELLING; measured in the
# review, a configuration file on a share made every relative path a network
# path, and a link (junction, symbolic link) in a local path was followed
# wherever it led. `_refuse_where_it_leads` applies the same refusals to the
# place a path LEADS to: it follows links component by component with
# `os.lstat`/`os.readlink`, which read the link itself and never open its
# target - `Path.resolve()` would open it, and so contact the very share it
# is meant to refuse. A drive letter that Windows maps to a network share is
# refused too (`_drive_is_remote`).
_LINK_LIMIT = 32
_DRIVE_REMOTE = 4  # GetDriveTypeW: DRIVE_REMOTE


def _drive_is_remote(drive: str) -> bool:
    """Whether `drive` (`Z:`) is a network drive. `GetDriveTypeW` reads the
    local drive mapping and opens nothing on the share."""
    if os.name != "nt" or len(drive) != 2 or drive[1] != ":":
        return False
    import ctypes

    return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == _DRIVE_REMOTE


def _refuse_led_to(plain: str, field: str, followed: bool) -> None:
    """The refusals of `_refuse_remote_or_stream` over a location the server
    computed (resolved against the configuration's directory, or reached
    through a link), and a network drive letter."""
    try:
        _refuse_remote_or_stream(plain, field)
    except ConfigError as exc:
        reason = str(exc)[len(field) + 1 :] if str(exc).startswith(field + " ") else str(exc)
        via = "via een junction of symbolische link" if followed else "na het oplossen"
        raise ConfigError(f"{field} leidt naar een plek die deze versie weigert ({via}): {reason}") from None
    drive = Path(plain).drive
    if _drive_is_remote(drive):
        raise ConfigError(
            f"{field} ligt op een netwerkstation ({drive}); deze versie leest alleen van een lokale schijf"
        )


def _refuse_where_it_leads(path: Path, field: str) -> None:
    """Follows `path` link by link without opening a target, and refuses
    when any step lands on a network or device path, an alternate data
    stream or a network drive. A component that does not exist (yet) ends
    the walk: there is nothing beyond it to follow. A reparse point that is
    no link (a cloud placeholder, deduplication) is an ordinary directory
    here. More than `_LINK_LIMIT` links is refused as well."""
    if os.name != "nt":
        return
    try:
        current = os.path.abspath(str(path))
    except (OSError, ValueError):
        return  # an unreadable spelling (a NUL character) is refused by the checks that read it
    followed = False
    for _ in range(_LINK_LIMIT):
        plain = _without_extended_prefix(current)
        _refuse_led_to(plain, field, followed)
        parts = Path(plain).parts
        walked = Path(parts[0]) if parts else Path(plain)
        redirected = None
        for index in range(1, len(parts)):
            walked = walked / parts[index]
            try:
                attributes = os.lstat(walked).st_file_attributes
            except (OSError, ValueError):
                return
            if not attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            try:
                target = os.readlink(walked)
            except (OSError, ValueError):
                continue
            if not _is_absolute_path(Path(target)):
                target = os.path.join(os.path.dirname(str(walked)), target)
            redirected = os.path.join(target, *parts[index + 1 :])
            break
        if redirected is None:
            return
        try:
            current = os.path.abspath(redirected)
        except (OSError, ValueError):
            current = redirected
        followed = True
    raise ConfigError(f"{field} loopt via meer dan {_LINK_LIMIT} koppelingen; zo'n pad wordt niet gevolgd")


def _config_path(value, field: str, base: Path) -> Path:
    """The path of `field` as the server uses it: `_refuse_remote_or_stream` first, then
    a relative path resolved against `base` (the directory of the
    configuration file), never against the working directory, and then the
    same refusals over where the result leads (`_refuse_where_it_leads`)."""
    text = _require_text(value, field)
    _refuse_remote_or_stream(text, field)
    candidate = Path(text)
    if _is_absolute_path(candidate):
        _refuse_where_it_leads(candidate, field)
        return candidate
    if candidate.drive or candidate.root:
        raise ConfigError(
            f"{field} hangt af van de huidige schijf of map (een schijf zonder map of een map zonder schijf);"
            f" schrijf het pad volledig uit of relatief aan de map van het configuratiebestand: {text!r}"
        )
    _refuse_where_it_leads(base / candidate, field)
    return base / candidate


def _relative_note(value, base: Path) -> str:
    """For a refusal over a path that was written RELATIVE: where it was
    resolved. Empty for an absolute path."""
    if isinstance(value, str) and not _is_absolute_path(Path(value.strip())):
        return f" (relatief pad, opgelost tegen de map van het configuratiebestand {base}, niet tegen de werkmap)"
    return ""


def _is_absolute_path(path: Path) -> bool:
    """Whether `path` names one place, whatever the working directory or
    the current drive, on every Python version the product supports.

    Measured on the CI runner: pathlib on Python 3.11 reads the extended
    spelling through a volume GUID (`\\\\?\\Volume{...}\\...`) as not
    absolute, where 3.12 reads it as absolute - so 3.11 refused that
    spelling of a code file before its containment was checked at all. On
    Windows a path behind the extended (`\\\\?\\`) or device (`\\\\.\\`)
    prefix (`_EXTENDED_PREFIXES`) is never resolved against the working
    directory, so the prefix alone makes it absolute: with a drive letter,
    `UNC\\` or a volume GUID behind it alike. Every other spelling keeps
    pathlib's rule of a drive AND a root, which reads the same on 3.11 and
    3.12. Deliberately not `os.path.isabs()`: before 3.13 that takes a root
    without a drive (`\\codes\\code.txt`) for absolute, while it lies on
    whatever drive is current."""
    if path.is_absolute():
        return True
    if os.name != "nt":
        return False
    text = str(path)
    return any(text.startswith(prefix) and len(text) > len(prefix) for prefix in _EXTENDED_PREFIXES)


def _comparable(path: Path) -> str:
    """The spelling two locations are compared in: resolved, the extended
    prefix peeled off (then resolved once more, so a `..` or a link the
    extended spelling kept is followed as well) and case-folded the way
    Windows compares it - the same fold `export.export_identity` uses."""
    text = str(path.resolve())
    if os.name == "nt":
        plain = _without_extended_prefix(text)
        if plain != text:
            text = str(Path(plain).resolve())
    return os.path.normcase(text)


def _as_written(path: Path) -> Path:
    """`path` the way the server itself uses it: made absolute, `..` taken
    away the way Windows does it for a path as written, and the extended
    prefix peeled off - but no link followed."""
    text = os.path.abspath(str(path))
    if os.name == "nt":
        text = _without_extended_prefix(text)
    return Path(text)


def _text_keys(path: Path) -> tuple[str, str]:
    """The two spellings of `path` the text comparison uses, both
    case-folded: where it resolves to (`_comparable`) and where it is
    written (`_as_written`)."""
    return _comparable(path), os.path.normcase(str(_as_written(path)))


def _lies_within(inner: Path, outer: Path) -> bool:
    """Whether `inner` is `outer` or lies somewhere below it, in whatever
    spelling either is written.

    Measured: `Path.resolve()` keeps the Windows extended spelling
    (`\\\\?\\C:\\...`, `\\\\?\\UNC\\localhost\\C$\\...`) as given, so a map
    inside the export map written that way compared as a map on another
    drive and was accepted. Measured as well: a map written through a link
    that lies IN the export map and points out of it was accepted, because
    only its resolved place was compared - while the server uses the path
    as written, and whoever writes the export map can replace that link by
    a real directory after the start. Two checks, either one enough to
    refuse, each on the resolved path AND on the path as written: the text
    of both paths (`_text_keys`), and - for a spelling no text rule can map
    back, such as the administrative share of the local disk
    (`\\\\localhost\\C$\\...`) - the identity of the directory itself:
    `outer` is compared by volume and file number with `inner` and every
    directory above it that exists, along both. Raises what
    `Path.resolve()` raises; the callers refuse that as "cannot be
    compared"."""
    inner_keys = _text_keys(inner)
    outer_keys = _text_keys(outer)
    for inner_key in inner_keys:
        for outer_key in outer_keys:
            if inner_key == outer_key or inner_key.startswith(outer_key.rstrip(os.sep) + os.sep):
                return True
    try:
        outer_stat = os.stat(outer)
    except (OSError, ValueError):
        return False
    if outer_stat.st_ino == 0:
        # No file number to compare by (some network file systems report
        # none); the text comparison above is all there is.
        return False
    resolved = inner.resolve()
    written = _as_written(inner)
    for candidate in (resolved, *resolved.parents, written, *written.parents):
        try:
            if os.path.samestat(os.stat(candidate), outer_stat):
                return True
        except (OSError, ValueError):
            continue
    return False


def _check_code_path(path: Path, forbidden_dirs: list[Path]) -> Path:
    """Absolute, not a directory, and outside every directory the product
    itself reads or writes. Returns the path, so the caller can pass it on.

    `path` !r-quoted in all four messages, and `forbidden` !r-quoted in the
    last two: both are operator-controlled configuration
    text (handelen.codekanaal.pad itself, and the directories derived from
    exportmap/handelen.fixturemap/handelen.schrijfscript/kennispad/doelen/
    verzamelscript that make up `forbidden_dirs`), never checked for control
    characters before this point - the previous round left this function
    named but deliberately unfixed ("apart te beoordelen"); this round
    closes it with the same pattern as _require_file() above, the same
    reachable class as the eight places already closed.

    A path `_lies_within` cannot compare (a NUL character, for one, which
    `Path.resolve()` refuses) is no path shown to lie outside: refused
    here, at the start, rather than at the first write. Absoluteness is
    read by `_is_absolute_path`, so every spelling reaches that check on
    every supported Python version."""
    if not _is_absolute_path(path):
        raise ConfigError(f"handelen.codekanaal.pad moet een absoluut pad zijn: {path!r}")
    if path.is_dir():
        raise ConfigError(f"handelen.codekanaal.pad is een map, geen bestand: {path!r}")
    for forbidden in forbidden_dirs:
        try:
            inside = _lies_within(path, forbidden)
        except (ValueError, OSError):
            raise ConfigError(
                "kan niet vaststellen dat handelen.codekanaal.pad buiten een map ligt die het product "
                f"zelf leest of schrijft ({forbidden!r}): {path!r}"
            ) from None
        if inside:
            raise ConfigError(
                "handelen.codekanaal.pad mag niet in een map staan die het product zelf "
                f"leest of schrijft ({forbidden!r}): {path!r}"
            )
    return path


def _require_comparable_export_dir(export_dir: Path) -> None:
    """The export map is the one map every other location is compared
    against; a spelling the comparison cannot read (a NUL character, for
    one, which `Path.resolve()` refuses) is refused HERE, over the export
    map itself. Measured before: the code-file check was the first to
    compare against it and refused with a reason about
    handelen.codekanaal.pad, a field the operator did not have to touch.
    Only the ValueError of an unreadable spelling is turned into a refusal;
    whether the map exists is still said by the existence check below.
    `export_dir` !r-quoted (operator text)."""
    try:
        _text_keys(export_dir)
    except ValueError:
        raise ConfigError(
            f"exportmap is geen pad dat de server kan vergelijken (bijvoorbeeld een NUL-teken): {export_dir!r}"
        ) from None


def _check_provenance_dir(provenance_dir: Path, export_dir: Path) -> None:
    """The provenance map and the export map may not lie in each other.

    Whoever supplies an export writes the export map: a provenance map inside
    it lets a record arrive WITH the export, and the target binding it
    proves falls away. Whoever replaces the export map also writes the map
    that holds it - the scan's own work map, the previous export and the lock
    lie there too - so an export map inside the provenance map is refused as
    well. Same form as `_check_code_path`: `_lies_within` on both paths,
    both !r-quoted (operator text), and a path it cannot compare refused."""
    for inner, outer, refusal, uncertain in (
        (
            provenance_dir,
            export_dir,
            f"de herkomstmap mag niet in de exportmap staan ({export_dir!r}): {provenance_dir!r}",
            f"kan niet vaststellen dat de herkomstmap buiten de exportmap ligt ({export_dir!r}): {provenance_dir!r}",
        ),
        (
            export_dir,
            provenance_dir,
            f"de exportmap mag niet in de herkomstmap staan ({provenance_dir!r}): {export_dir!r}",
            f"kan niet vaststellen dat de exportmap buiten de herkomstmap ligt ({provenance_dir!r}): {export_dir!r}",
        ),
    ):
        try:
            inside = _lies_within(inner, outer)
        except (ValueError, OSError):
            raise ConfigError(uncertain) from None
        if inside:
            raise ConfigError(refusal)


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _script_policy(raw: dict) -> ScriptPolicy:
    """1.0.2: `scriptpin` (file name -> sha256, lower-case hex, from
    `python -m nsmcp.powershell --pin`) and `uitvoeringsbeleid` (one of
    `EXECUTION_POLICIES`). Absent `scriptpin`: no check, as before - named in
    the documentation, never a silent pass of a broken pin."""
    pins = None
    if "scriptpin" in raw:
        value = raw["scriptpin"]
        if not isinstance(value, dict) or not value:
            raise ConfigError("scriptpin moet een niet-leeg object zijn: bestandsnaam -> sha256")
        pins = {}
        for name, digest in value.items():
            if (
                not isinstance(name, str)
                or not name.strip()
                or name != name.strip()
                or any(sep in name for sep in ("/", "\\", ":"))
                or name in (".", "..")
            ):
                raise ConfigError(f"scriptpin: een sleutel moet een kale bestandsnaam zijn: {name!r}")
            if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
                raise ConfigError(f"scriptpin: de pin van {name!r} is geen sha256 (64 kleine hex-tekens)")
            key = name.casefold()
            if key in pins:
                raise ConfigError(f"scriptpin: {name!r} staat er twee keer in (hoofdletters tellen niet)")
            pins[key] = digest
    policy = DEFAULT_EXECUTION_POLICY
    if "uitvoeringsbeleid" in raw:
        policy = raw["uitvoeringsbeleid"]
        if policy not in EXECUTION_POLICIES:
            raise ConfigError(f"onbekend uitvoeringsbeleid: {policy!r}; toegestaan: {', '.join(EXECUTION_POLICIES)}")
    return ScriptPolicy(pins=pins, execution_policy=policy)


PSEUDONYM_TABLE_NAME = "openheid-vertaaltabel.json"


def _check_pseudonym_table_dir(table: Path, export_dir: Path) -> None:
    """1.0.2: the pseudonym table may not lie in the export map nor in
    the directory that holds it. Both are refused with the remedy; a path
    that cannot be compared is refused too."""
    refusal = (
        f"bij openheid 'beperkt' staat de vertaaltabel naast het configuratiebestand (of in"
        f" onderhoud.ledgermap), en die map is de exportmap of de map eromheen ({export_dir!r}) - die kan"
        " schrijven wie de export aanlevert; zet het configuratiebestand in een eigen beheermap: "
        f"{table!r}"
    )
    try:
        if _lies_within(table, export_dir) or _comparable(table.parent) == _comparable(export_dir.parent):
            raise ConfigError(refusal)
    except (ValueError, OSError):
        raise ConfigError(f"kan niet vaststellen dat de vertaaltabel buiten de exportmap ligt: {table!r}") from None


def _check_export_boundaries(
    export_dir: Path,
    *,
    inside: list[tuple[str, Path | None]],
    around: list[tuple[str, Path]],
) -> None:
    """The export map is the ONE map a supplying party may write. Nothing the
    server reads, runs or writes may lie in it (`inside`: a knowledge file
    or target file there is content that party chooses, a collect script,
    runner or write script there is code that party runs through this
    server, a ledger, register or firmware map there is state that party
    rewrites), and the maps the product itself writes or picks a firmware
    bundle from may not hold it (`around`: whoever replaces the export map
    writes the map around it - the scan's work map, the previous export and
    the lock lie there). Measured before: only the provenance map and the
    code file were held against the export map; everything else in it
    started without a word.

    The same `_lies_within` both ways as `_check_provenance_dir`, with the
    same rule for a path it cannot compare: refused, never assumed outside.
    Every path !r-quoted (operator text), and every refusal names its field.

    Deliberately NOT in `around`: the map of the configuration file and the
    maps of the scripts. The configuration example in the manual (and
    `config.example.json`) puts configuration, knowledge, collect script and
    export under one administrative map - safe while that map is an
    administrative one and the server collects the export itself, as the
    manual says. The configuration file and every script in the export map
    ARE refused (`inside`), which covers an export map that IS one of those
    maps."""
    for veld, pad in inside:
        if pad is None:
            continue
        try:
            binnen = _lies_within(pad, export_dir)
        except (ValueError, OSError):
            raise ConfigError(
                f"kan niet vaststellen dat {veld} buiten de exportmap ligt ({export_dir!r}): {pad!r}"
            ) from None
        if binnen:
            raise ConfigError(
                f"{veld} ligt in de exportmap ({export_dir!r}): {pad!r}; die map mag een aanleverende partij "
                "beschrijven, dus wat de server leest, uitvoert of schrijft hoort daar niet in"
            )
    for veld, pad in around:
        try:
            binnen = _lies_within(export_dir, pad)
        except (ValueError, OSError):
            raise ConfigError(
                f"kan niet vaststellen dat de exportmap buiten {veld} ligt ({pad!r}): {export_dir!r}"
            ) from None
        if binnen:
            raise ConfigError(
                f"de exportmap ligt in {veld} ({pad!r}): {export_dir!r}; wie de export vervangt, schrijft in "
                "de map eromheen"
            )


def build_server_from_config(path: Path) -> FastMCP:
    """THE one place that turns a configuration file into a built
    FastMCP server object (NOT yet started - see run()). Everything that is
    testable without starting a real stdio server flows through here:
    structural config validation (load_config), field-type checks, the
    profile decision (load_profile - profile.py, unchanged) and the
    profile-specific rule for dienst."""
    raw = load_config(path)

    profile_name = _require_text(raw["profiel"], "profiel")
    try:
        profile = load_profile(profile_name)
    except ValueError as exc:
        # load_profile() (profile.py, unchanged) stays with a ValueError -
        # that is its own, correct contract. Here on the seam it is turned
        # into ConfigError (message unchanged) so build_server_from_config()
        # raises ONE error class for every rejection, not two. run()'s
        # except tuple therefore needs no bare ValueError anymore - and a
        # real programming error thus stays visible as a traceback instead
        # of silently appearing as "Fout: ...".
        raise ConfigError(str(exc)) from None

    if "openheid" in raw:
        disclosure_name = _require_text(raw["openheid"], "openheid")
        try:
            disclosure = load_disclosure(disclosure_name)
        except ValueError as exc:
            # load_disclosure() (disclosure.py, unchanged) stays with a
            # ValueError - same conversion to ConfigError as for the profile
            # above, message unchanged.
            raise ConfigError(str(exc)) from None
    else:
        disclosure = Disclosure.FULL

    retention = None
    if "bewaren" in raw:
        section = raw["bewaren"]
        if not isinstance(section, dict):
            raise ConfigError("bewaren moet een object zijn met exports_per_doel en vrije_ruimte_vloer_mb")
        if section.keys() - {"exports_per_doel", "vrije_ruimte_vloer_mb"}:
            raise ConfigError("bewaren bevat een onbekend veld; toegestaan: exports_per_doel, vrije_ruimte_vloer_mb")
        count = section.get("exports_per_doel", 5)
        floor = section.get("vrije_ruimte_vloer_mb", 2048)
        for name, value in (("exports_per_doel", count), ("vrije_ruimte_vloer_mb", floor)):
            if type(value) is not int or value < 0:
                raise ConfigError(f"bewaren.{name} moet een geheel getal van 0 of hoger zijn")
        retention = Retention(enabled=count > 0, count=count, floor_mb=floor)

    chapters = CHAPTERS
    if "hoofdstukken" in raw:
        value = raw["hoofdstukken"]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError("hoofdstukken moet een lijst van teksten zijn")
        if not value:
            # Security 20: an empty list used to build a SILENT server with
            # zero tools. That is not a configuration, it is a mistake that
            # looks like a running product - refuse it where the operator can
            # still see it.
            raise ConfigError("hoofdstukken mag niet leeg zijn; laat het veld weg om alle hoofdstukken aan te zetten")
        chosen = frozenset(v.strip().lower() for v in value)
        unknown_chapters = chosen - CHAPTERS
        if unknown_chapters:
            # !r-quoted per chapter: `unknown_chapters` is
            # operator text from `hoofdstukken` - .strip() removes only
            # leading/trailing whitespace, an embedded newline survives.
            # `CHAPTERS` stays bare: a fixed, known-safe frozenset.
            raise ConfigError(
                "onbekend hoofdstuk: "
                f"{', '.join(repr(v) for v in sorted(unknown_chapters))}; "
                f"toegestaan: {', '.join(sorted(CHAPTERS))}"
            )
        chapters = chosen

    # Constructed BEFORE the handelen block: `codekanaal` needs to know which
    # directories the product itself reads, and these are those directories.
    # Only the CONSTRUCTION moves up - the existence checks stay below, so the
    # order in which an operator hears about a missing file is unchanged.
    base = path.resolve().parent
    export_dir = _config_path(raw["exportmap"], "exportmap", base)
    _require_comparable_export_dir(export_dir)
    knowledge_path = _config_path(raw["kennispad"], "kennispad", base)
    # Absent is allowed and is NOT a pass: the package then loads, but every
    # floor and CVE statement on it says `[niet vastgesteld]` (see
    # `build_server(knowledge_pin=...)`).
    knowledge_pin = _kennispin(raw["kennispin"]) if "kennispin" in raw else None
    script_policy = _script_policy(raw)
    targets_path = _config_path(raw["doelen"], "doelen", base) if "doelen" in raw else None
    collect_script = _config_path(raw["verzamelscript"], "verzamelscript", base) if "verzamelscript" in raw else None

    action_script = None
    fixture_dir = None
    code_presenter = None
    allowlist = Allowlist(per_target={})
    forbidden_addresses: tuple[str, ...] = ()
    if "handelen" in raw:
        # The openheid condition that used to demand 'volledig' is gone: it
        # existed because the writing tools composed their own answer text and
        # never travelled through the disclosure seam, and because a refusal
        # named the whole allowlist - both repaired, failure branches
        # included (`_failure()` in mcp_server._act()). `handelen` combines
        # with 'volledig' and with 'beperkt', and what the level decides is
        # what a caller reads back: pseudonyms there, the real names here.
        #
        # 'minimaal' is refused, and for a different reason than the old gate
        # gave. Nothing leaks there - that rendering says less, not more. It
        # cannot CARRY a write proposal: it summarises an answer down to
        # counts, so the VOORSTEL line, the arguments and the line telling the
        # caller to ask the administrator for the code all disappear, while a
        # confirmation code is issued and shown to that administrator all the
        # same. That is a two-step flow whose second step cannot be reached.
        # `build_server()` carries the same gate for a caller that bypasses
        # this loader; there it drops the seven tools with a message on stderr,
        # because a library call cannot exit the process.
        if disclosure is Disclosure.MINIMAL:
            raise ConfigError(
                "de sectie handelen gaat niet samen met openheid minimaal: die weergave vat "
                "een antwoord samen tot tellingen, dus een voorstel verliest zijn regels en "
                "de aanwijzing om deze tool opnieuw aan te roepen met de bevestigingscode - "
                "terwijl die code wel aan de beheerder getoond wordt. Kies openheid beperkt "
                "(de aanroeper werkt dan met pseudoniemen) of volledig"
            )
        section = raw["handelen"]
        if not isinstance(section, dict):
            raise ConfigError("handelen moet een object zijn met schrijfscript, fixturemap en codekanaal")
        unknown_action_fields = section.keys() - _HANDELEN_FIELDS - _HANDELEN_OPTIONAL_FIELDS
        if unknown_action_fields:
            # !r-quoted per field: `unknown_action_fields`
            # is `section.keys()`, JSON keys the operator typed under
            # `handelen` - not yet checked for control characters.
            raise ConfigError(f"onbekend veld in handelen: {', '.join(repr(v) for v in sorted(unknown_action_fields))}")
        missing_action_fields = _HANDELEN_FIELDS - section.keys()
        if missing_action_fields:
            # The reason is spelled out for `codekanaal` specifically: an
            # existing configuration from before this version breaks here on
            # purpose, and "mist veld: codekanaal" alone would leave the
            # operator guessing what the field is for.
            reden = ""
            if "codekanaal" in missing_action_fields:
                reden = (
                    "; codekanaal zegt WAAR de bevestigingscode heen gaat - hij staat niet "
                    "meer in het antwoord van het gereedschap, want dat leest het model mee. "
                    'Kies {"soort": "venster"} (een venster op deze machine) of '
                    '{"soort": "bestand", "pad": "<absoluut pad>"} om te oefenen'
                )
            if "toegestaan" in missing_action_fields:
                reden += (
                    "; de allowlist komt sinds 1.0 uit de configuratie en niet meer uit de "
                    "code. Zet 'toegestaan' in de handelen-sectie: per doelnaam per handeling "
                    "de toegestane waarden, of true/false voor een handeling die haar object "
                    "zelf vormt. Een lege sectie ({}) is geldig en betekent: niets toegestaan"
                )
            raise ConfigError(f"handelen mist veld: {', '.join(sorted(missing_action_fields))}{reden}")
        action_script = _config_path(section["schrijfscript"], "handelen.schrijfscript", base)
        fixture_dir = _config_path(section["fixturemap"], "handelen.fixturemap", base)
        _require_file(action_script, "handelen.schrijfscript")
        if not fixture_dir.is_dir():
            # !r-quoted: `fixture_dir` is operator text
            # from handelen.fixturemap, the SAME shape as _require_file()'s
            # two messages right above - but this check never went through
            # that shared helper, so the sweep that fixed _require_file()
            # would have walked straight past it without a dedicated look
            # at every ConfigError site in this function.
            raise ConfigError(f"handelen.fixturemap is geen map: {fixture_dir!r}")

    onderhoud = None
    if "onderhoud" in raw:
        onderhoud = _onderhoud_config(raw["onderhoud"], handelen_configured="handelen" in raw, base=base)

    # Where `status_ververs` records which exports this server collected:
    # OUTSIDE the export map, in a directory the writing tools already own
    # (the ledger map) or, without one, under the configuration's own
    # directory - never beside the export map, which whoever supplies an
    # export can write as well. `_check_provenance_dir` below refuses a
    # configuration that puts either map inside the other.
    provenance_dir = (
        Path(onderhoud.ledgermap) / "herkomst" if onderhoud is not None else path.resolve().parent / "herkomst"
    )

    if "handelen" in raw:
        # The code channel comes AFTER `onderhoud`: the maps the maintenance
        # half reads and writes - the ledger map with the provenance map in
        # it, the action register's map, the firmware map and the runner's
        # own map - are maps the code file and the sso presenter may not sit
        # in either. Measured before: `pad` = `<ledgermap>\herkomst\
        # herkomst.jsonl` or the action register itself started, and every
        # proposal then overwrote the provenance record or the register.
        section = raw["handelen"]
        gelezen_mappen = [export_dir, fixture_dir, action_script.parent, provenance_dir]
        gelezen_mappen += [pad.parent for pad in (knowledge_path, targets_path, collect_script) if pad is not None]
        if onderhoud is not None:
            gelezen_mappen += [onderhoud.ledgermap, onderhoud.firmwaremap, onderhoud.runner.parent]
            if onderhoud.actieregister is not None:
                gelezen_mappen.append(onderhoud.actieregister.parent)
        code_presenter = _code_channel(section["codekanaal"], gelezen_mappen)
        allowlist = _allowlist(section["toegestaan"])
        if "verboden_adressen" in section:
            forbidden_addresses = _verboden_adressen(section["verboden_adressen"])

    if profile is Profile.SERVICE and (targets_path is not None or collect_script is not None):
        raise ConfigError(
            "profiel 'dienst' beantwoordt alleen op een aangeleverde export; scannen ligt "
            "voor dit profiel buiten scope, dus 'doelen'/'verzamelscript' configureren wordt "
            "geweigerd in plaats van stilzwijgend genegeerd"
        )

    # With only one of the two present (and existing) the server used to
    # build right through - every tool registered, run() reached
    # server.run() and returned exit code 0, while scanning without the
    # missing half is impossible. For afgeschermd/online
    # (dienst is already handled above: those profiles may carry neither
    # field) this is no no-op but an operator who put down HALF a scan
    # configuration - that is an error, not a valid in-between form. Two
    # separate messages (not "doelen en/of verzamelscript onvolledig") so
    # the operator immediately knows which half is missing, without having
    # to compare.
    if (targets_path is None) != (collect_script is None):
        if targets_path is None:
            raise ConfigError(
                "doelen ontbreekt terwijl verzamelscript wel is ingesteld; scannen heeft "
                "beide nodig - zonder doelen weet de server niet WAT te scannen, en zonder "
                "deze weigering zou hij toch status_ververs aanbieden, dat een scan belooft "
                "die niet kan werken"
            )
        raise ConfigError(
            "verzamelscript ontbreekt terwijl doelen wel is ingesteld; scannen heeft beide "
            "nodig - zonder verzamelscript kan de server niet scannen, en zonder deze "
            "weigering zou hij toch status_ververs aanbieden, dat een scan belooft die niet "
            "kan werken"
        )

    # A configured path that does not exist is not "no targets" - that is
    # load_targets()'s (target.py, unchanged) correct contract for the
    # UNconfigured case, and that contract stays untouched here. But if the
    # operator did put down a path here, they meant something by it;
    # silently building on would start a half-configured server that offers
    # status_ververs while scanning is impossible.
    if targets_path is not None:
        _require_file(targets_path, "doelenbestand")
    if collect_script is not None:
        _require_file(collect_script, "verzamelscript")

    # CODEPOORT 1 PUNT 9. README.md promises a Dutch `Fout: ...` line and
    # exit code 1 for a bad configuration; measured, a configuration with a
    # nonexistent exportmap and kennispad simply started, and only every
    # ANSWER reported the paths as a read gap. That is a defensible design -
    # but not the one the documentation describes, and for a product whose
    # core claim is fail-closed the unkept promise costs more than the hole.
    # The decision (design par. 2.6) is to keep the promise.
    #
    # A path that EXISTS but is a FILE (an operator pointing at
    # export-manifest.json or at a zip) must not be told "niet gevonden" -
    # the path is right there, just the wrong kind. Same discipline as
    # handelen.fixturemap's "is geen map" and _require_file's "is een map,
    # geen bestand" (see their docstrings): say what the path actually is,
    # not that it is missing.
    if export_dir.exists() and not export_dir.is_dir():
        raise ConfigError(f"exportmap is geen map: {export_dir}{_relative_note(raw['exportmap'], base)}")
    if not export_dir.is_dir():
        raise ConfigError(f"exportmap niet gevonden: {export_dir}{_relative_note(raw['exportmap'], base)}")
    _check_provenance_dir(provenance_dir, export_dir)
    # After the provenance check on purpose: a ledger map or a configuration
    # file in the export map keeps the refusal it already had (its provenance
    # map lies there too); everything else now gets a refusal of its own.
    _check_export_boundaries(
        export_dir,
        inside=[
            ("het configuratiebestand", path),
            ("kennispad", knowledge_path),
            ("doelen", targets_path),
            ("verzamelscript", collect_script),
            ("handelen.schrijfscript", action_script),
            ("handelen.fixturemap", fixture_dir),
            *(
                [
                    ("onderhoud.runner", onderhoud.runner),
                    ("onderhoud.ledgermap", onderhoud.ledgermap),
                    ("onderhoud.firmwaremap", onderhoud.firmwaremap),
                    ("onderhoud.actieregister", onderhoud.actieregister),
                ]
                if onderhoud is not None
                else []
            ),
        ],
        around=(
            [("onderhoud.ledgermap", onderhoud.ledgermap), ("onderhoud.firmwaremap", onderhoud.firmwaremap)]
            if onderhoud is not None
            else []
        ),
    )
    _require_file(knowledge_path, "kennispad")
    if onderhoud is not None:
        # The target-name GRAMMAR needs only `toegestaan` (just
        # built above), not the target file - checked first, so a
        # misnamed target is refused over its own name rather than only
        # once a later check happens to need the target file too.
        _require_safe_upgrade_target_names(allowlist)
        # The sixth start error - checked LAST, deliberately: it needs
        # `toegestaan` (just built above) AND the target file (just
        # confirmed to exist above) both read, and runs over every target
        # the allowlist grants the tool to, not only the configured ones -
        # see `_require_upgrade_hostkeys()`.
        doelen = load_targets(targets_path) if targets_path is not None else {}
        _require_upgrade_hostkeys(allowlist, doelen)
        # Same scope, same moment - a PRESENT pin must also be valid
        # hex, or build_upgrade_arguments() crashes on it mid-phase-call
        # with a bare ValueError instead of a diagnosable start error.
        _require_hex_upgrade_hostkeys(allowlist, doelen)
        # Same scope, same moment - `adres` must be a literal IPv4 for
        # every target this allowlist grants the tool to, or `secondary_gate`
        # (nsmcp.upgrade) can never match Node ID 0's own IP against it.
        _require_ip_upgrade_targets(allowlist, doelen)
    if targets_path is not None:
        doelen_in_bestand = load_targets(targets_path)
        _require_printable_targets(doelen_in_bestand)
        _require_one_target_per_address(doelen_in_bestand)

    # 1.0.2: the pseudonym table and its lock in the management
    # directory - the same choice as the provenance map above (the ledger
    # map, or the configuration's own directory) - and never in or around
    # the export map, which whoever supplies an export may write. Only
    # 'beperkt' uses the table, so only there is that refused.
    pseudonym_table_path = (
        Path(onderhoud.ledgermap) if onderhoud is not None else path.resolve().parent
    ) / PSEUDONYM_TABLE_NAME
    if disclosure is Disclosure.LIMITED:
        _check_pseudonym_table_dir(pseudonym_table_path, export_dir)

    return build_server(
        export_dir,
        knowledge_path,
        pseudonym_table_path=pseudonym_table_path,
        script_policy=script_policy,
        targets_path=targets_path,
        collect_script=collect_script,
        disclosure=disclosure,
        chapters=chapters,
        action_script=action_script,
        fixture_dir=fixture_dir,
        code_presenter=code_presenter,
        **({"retention": retention} if retention is not None else {}),
        allowlist=allowlist,
        onderhoud=onderhoud,
        forbidden_addresses=forbidden_addresses,
        knowledge_pin=knowledge_pin,
        provenance_dir=provenance_dir,
    )


def run(argv: list[str] | None = None) -> int:
    """Reads argv, builds the server via build_server_from_config(), starts
    it on stdio. The REAL, blocking stdio server is never spawned in the
    test suite - that would hang a test run. Nearly every test in
    tests/test_start.py therefore ends in an error path (exit code 1 or 2)
    and never reaches server.run(). The valid path IS covered: FastMCP.run
    is replaced there by a monkeypatched spy that proves run() is called
    exactly once (proven with a mutation test)."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or arguments[0].startswith("-"):
        # A single argument starting with '-'/'--' (such as --help or -h) is
        # a usage question, not a configuration path - otherwise
        # load_config() reports "configuratiebestand niet gevonden: --help",
        # which only confuses the operator.
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        server = build_server_from_config(Path(arguments[0]))
    except (ConfigError, TargetError) as exc:
        # ConfigError: all our own rejections, INCLUDING an unknown
        # profile - load_profile()'s ValueError (profile.py, unchanged) is
        # already converted to ConfigError on the seam in
        # build_server_from_config(), so no bare ValueError needs catching
        # here. That is deliberate: a ValueError surfacing HERE is a real
        # programming error, and it must stay visible as a traceback, not
        # be silently swallowed as "Fout: ...".
        #
        # TargetError (target.py): build_server() loads a configured
        # targets file IMMEDIATELY when building the server (load_targets()
        # in mcp_server.py), not at the first tool call. Without this
        # branch a broken targets file escapes as a raw traceback on
        # stderr instead of the same tidy 'Fout: ...' line every other
        # rejection gets here - see
        # test_main_with_broken_targets_file_prints_error_and_returns_exit_code_1_no_traceback.
        print(f"Fout: {exc}", file=sys.stderr)
        return 1
    # SECURITY 14. Explicit, not the FastMCP default. The default IS stdio
    # today, but a default is not a promise: this product's socket guarantee
    # rests on the transport, so it is written down here and pinned by
    # tests/test_start.py.
    server.run(transport="stdio")
    return 0


def main() -> None:  # pragma: no cover - console_scripts entry, thin glue
    raise SystemExit(run())


# SECURITY 23. Without this `python -m nsmcp.start <config>` did nothing and
# returned exit code 0 - a silent no-op that reads as success. Only the console
# script worked, and that difference cost the security spike an invalid first
# measurement.
if __name__ == "__main__":  # pragma: no cover - exercised in a subprocess test
    raise SystemExit(run())
