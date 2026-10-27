"""Pytest base settings.

Why this file exists: pytest puts its temporary directories under the user's
shared temp directory by default. When that directory gets damaged - broken
permissions after a stuck process, another user who created it - EVERY test
that uses `tmp_path` fails with a PermissionError while nothing is wrong with
the code. That happened on this project's development machine: 58 of the 144
tests produced an error that looked like a code defect and was not.

By giving pytest its own base directory inside the project, the suite no
longer depends on the state of a shared system directory. Whoever clones this
repo runs `pytest` and gets an honest result - no environment noise that
looks like a defect.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from nsmcp.handelen import Allowlist, MaintenanceConfig
from nsmcp.mcp_server import build_server

# The ONE place the tests learn which Posh-SSH version the transport pins:
# `$vereist` in scripts/GjkUpgrade-Ssh.ps1, read as written. The documents
# (tests/test_docs_claims.py) and the transport tests
# (tests/test_runner_script.py) both take it from here, so a new pin is one
# edit in the script and every place that names the old one goes red.
_TRANSPORT = Path(__file__).resolve().parent.parent / "scripts" / "GjkUpgrade-Ssh.ps1"
_POSH_SSH_PIN = re.compile(r"^\s*\$vereist = '(?P<versie>\d+\.\d+\.\d+)'\s*$", re.MULTILINE)


def posh_ssh_pin() -> str:
    """The pinned Posh-SSH version, exactly one `$vereist = 'x.y.z'` line."""
    treffers = _POSH_SSH_PIN.findall(_TRANSPORT.read_text(encoding="ascii"))
    assert len(treffers) == 1, f"verwacht precies een $vereist-regel in {_TRANSPORT.name}, gevonden: {treffers}"
    return treffers[0]


# ---------------------------------------------------------------------------
# 1.1 B.3 point 3: the runtime seam check. ONE audit hook for the whole
# session (an audit hook cannot be removed again), active only inside the
# `open_audit` fixture. It fails a test on every `open` audit event with a
# text, bytes or path argument that comes from product code (`src/nsmcp`)
# other than `localpath`: the innermost frame of this repository in the stack
# decides. Test code opening its own fixtures is not product code. A handle
# open in `localpath` (`NtCreateFile` through ctypes) raises no `open` event
# at all. Exempt by their installation path (B.3 exception 1): the standard
# library, the installed environment and the package's own source, which
# the import system reads; and the pinned exception list of
# tests/test_read_inventory.py, by file and function.
# ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_PRODUCT = _REPO / "src" / "nsmcp"
_TESTS = _REPO / "tests"
_OPEN_AUDIT: dict = {"active": False, "violations": []}


def _installation_paths() -> tuple[str, ...]:
    import sys
    import sysconfig

    places = {sys.prefix, sys.base_prefix, sys.exec_prefix, str(_PRODUCT)}
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        with __import__("contextlib").suppress(KeyError):
            places.add(sysconfig.get_paths()[key])
    return tuple(os.path.normcase(os.path.abspath(place)) + os.sep for place in places if place)


_INSTALLED = _installation_paths()


def _audit_open(event: str, args: tuple) -> None:
    if event != "open" or not _OPEN_AUDIT["active"]:
        return
    target = args[0] if args else None
    if not isinstance(target, (str, bytes, os.PathLike)):
        return  # a file descriptor or a handle: no path argument
    import sys

    frame = sys._getframe(1)
    while frame is not None:
        name = frame.f_code.co_filename
        try:
            place = Path(name).resolve()
        except (OSError, ValueError):
            frame = frame.f_back
            continue
        if place.is_relative_to(_TESTS):
            return  # test code opening its own fixtures
        if place.is_relative_to(_PRODUCT):
            break
        frame = frame.f_back
    else:
        return  # no product frame on the stack: pytest, the event loop
    module = Path(frame.f_code.co_filename).name
    function = frame.f_code.co_qualname
    if module == "localpath.py":
        return
    text = os.fsdecode(target) if isinstance(target, (bytes, os.PathLike)) else target
    normalized = os.path.normcase(os.path.abspath(text))
    if normalized.startswith(_INSTALLED):
        return
    from test_read_inventory import runtime_exception

    if runtime_exception(module, function, text):
        return
    _OPEN_AUDIT["violations"].append(f"{module}:{function} opende {text!r} (modus {args[1] if len(args) > 1 else '?'})")


__import__("sys").addaudithook(_audit_open)


@pytest.fixture
def open_audit():
    """Activates the runtime seam check for one test; fails the test when a
    product open by path happened outside `localpath` and the exceptions."""
    _OPEN_AUDIT["violations"] = []
    _OPEN_AUDIT["active"] = True
    try:
        yield _OPEN_AUDIT["violations"]
    finally:
        _OPEN_AUDIT["active"] = False
    violations = list(_OPEN_AUDIT["violations"])
    _OPEN_AUDIT["violations"] = []
    assert violations == [], "product opende een pad buiten localpath:\n" + "\n".join(violations)


def pytest_configure(config: pytest.Config) -> None:
    """Give pytest its own temporary base directory inside the project."""
    if config.getoption("basetemp", default=None):
        return  # the caller chose a directory itself; that wins
    own_dir = Path(__file__).resolve().parent.parent / ".pytest-tmp"
    own_dir.mkdir(parents=True, exist_ok=True)
    config.option.basetemp = own_dir


def _export_dir(tmp_path: Path) -> Path:
    """The smallest export build_server() will accept. Shared here because
    more than one test file builds a real server only to inspect its TOOL
    REGISTER (which names exist, what a name's description says) rather
    than to exercise an answer - test_firmware_boundary.py is the first,
    but not meant to be the last."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir(parents=True)
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-19T10:00:00.0000000Z",
        "resources": {"config/sslcertkey": {"status": "EMPTY"}},
        "files": {},
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return export_dir


def _knowledge_file(tmp_path: Path) -> Path:
    knowledge_path = tmp_path / "kennis.json"
    knowledge_path.write_text(json.dumps({"versie": "2026.08", "datum": "2026-08-16", "cve": []}), encoding="utf-8")
    return knowledge_path


class BuiltServer:
    """A real FastMCP server (from build_server()), wrapped for the two
    questions a test asks about a TOOLREGISTER: which names are on it, and
    what a name's own description says - without every test repeating
    `asyncio.run(server.list_tools())` and the dict comprehension around it.

    Deliberately thin: this reads the REAL registered tool list once, at
    construction, through the real MCP tool listing path (not a private
    attribute of FastMCP) - the same path an AI client uses."""

    def __init__(self, server) -> None:
        self.server = server
        self._tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}

    def tool_names(self) -> set[str]:
        return set(self._tools)

    def description_of(self, name: str) -> str:
        return self._tools[name].description


def _handelen_server(tmp_path: Path):
    """A real server built WITH a `handelen` section configured, so every
    writing tool that CAN register on this branch, does. Shared between the
    `built_server` fixture below - which wraps the result
    for the two TOOLREGISTER questions a NAME/DESCRIPTION test asks - and
    test_product_surface.py's own pinned-schema test, which needs the raw
    FastMCP server object itself: it reads `inputSchema` too, not only
    `description`, so it cannot go through `BuiltServer`. Before this fix
    round the two files built this same server line for line; now the
    construction lives here once. Nothing here ever calls the write
    script; `code_presenter` is a no-op because listing tools never
    reaches a confirmation.

    The allowlist grants `config_opslaan` - that tool registers only where a
    target may run it - and deliberately NOT `onderhoud_upgrade_fase`: the
    firmware-boundary tests read their branch off whether the runner is
    registered here."""
    script = tmp_path / "schrijf.ps1"
    script.write_text("# leeg; deze fixture voert niets uit", encoding="utf-8")
    return build_server(
        _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        action_script=script,
        fixture_dir=tmp_path,
        code_presenter=lambda *args: None,
        onderhoud=maintenance_config(tmp_path),
        allowlist=Allowlist(per_target={"lab": {"config_opslaan": True}}),
    )


@pytest.fixture
def built_server(tmp_path: Path) -> BuiltServer:
    """A real server built WITH a `handelen` section configured, so every
    writing tool that CAN register on this branch, does - the same
    construction test_product_surface.py uses to reach its fifteen-tool
    baseline (`_handelen_server` above, shared by both)."""
    return BuiltServer(_handelen_server(tmp_path))


def expiry_text_today(days_at_scan: int, scan_day: str) -> str:
    """The expiry outcome a session answer must carry TODAY for a
    certificate the export saw at `days_at_scan` on `scan_day` (YYYY-MM-DD):
    the days count from today, minus the age of the export (1.0.2)."""
    from datetime import UTC, date, datetime

    remaining = days_at_scan - (datetime.now(UTC).date() - date.fromisoformat(scan_day)).days
    return "is verlopen" if remaining < 0 else f"verloopt over {remaining} dagen"


def seal_manifest(directory: Path) -> None:
    """Writes the `payloadSha256` the REAL collector writes, for every object
    file a hand-built export happens to carry.

    Why this exists as a shared helper: `Export._object_payload` verifies an
    object file against the manifest (security 3), and a synthetic export that
    skips the hash would fail that check for the wrong reason - the test's own
    manifest instead of the behaviour under test. Call it AFTER writing the
    manifest, and again after any test that rewrites an object file on purpose.

    Deliberately silent when there is nothing to seal: several tests write a
    broken or absent manifest ON PURPOSE, and this helper must not repair that.
    """
    import hashlib
    import json

    manifest_path = directory / "export-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(manifest, dict):
        return
    resources = manifest.get("resources")
    if not isinstance(resources, dict):
        return
    for resource, entry in resources.items():
        if not isinstance(entry, dict):
            continue
        # The same derivation `_object_payload` makes: last path segment,
        # without any query string.
        name = str(resource).split("/")[-1].split("?", 1)[0]
        payload = directory / "objects" / f"{name}.json"
        if not payload.is_file():
            continue
        entry["payloadSha256"] = hashlib.sha256(payload.read_bytes()).hexdigest().upper()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def add_cert_usage_sources(directory: Path) -> None:
    """Adds the three sources of the certificate use outside the bindings
    (`nsmcp.cert_usage`) to a hand-built export: both SAML object sources and
    the SSL servicegroup file, read and EMPTY, with the object source the
    servicegroup file declares for its parent list.

    Why this exists as a shared helper: "los" is the claim that NOTHING uses a
    certificate, and it needs every source that could refute it read. A
    hand-built export that stands for a complete read of an appliance carries
    these three too; one without them now honestly answers "onbekend" (bron
    niet in de export), which is exactly not what such a test is about. Call
    it AFTER writing the manifest.
    """
    import hashlib
    import json

    manifest_path = directory / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    resources = manifest.setdefault("resources", {})
    for resource in (
        "config/authenticationsamlaction",
        "config/authenticationsamlidpprofile",
        "config/sslservicegroup",
    ):
        resources[resource] = {"status": "EMPTY"}
    name = "sslservicegroup_sslcertkey_binding.by-parent.json"
    raw = json.dumps(
        {
            "bindingResource": "sslservicegroup_sslcertkey_binding",
            "parentResource": "sslservicegroup",
            "parentKey": "servicegroupname",
            "shape": "list",
            "parents": [],
        }
    )
    (directory / "bindings").mkdir(exist_ok=True)
    (directory / "bindings" / name).write_text(raw, encoding="utf-8")
    manifest.setdefault("files", {})[f"bindings/{name}"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def knowledge_pin_for(knowledge_path: Path):
    """The `kennispin` an operator would configure for this package: its
    version and canonical digest, computed the way
    `python -m nsmcp.knowledge --digest` does. A test server built with it
    stands for a configuration that approved exactly this package; change the
    package afterwards and the server refuses it, as it should."""
    from nsmcp.knowledge import KnowledgePin, canonical_digest

    raw = json.loads(knowledge_path.read_text(encoding="utf-8"))
    return KnowledgePin(version=str(raw["versie"]).strip(), digest=canonical_digest(raw))


def provenance_dir_for(export_dir: Path) -> Path:
    """Where a test server keeps its provenance records: a `herkomst` map in
    a `config` map beside the test's export map - the test's stand-in for
    the configuration directory start.py uses. Never inside the export."""
    return Path(export_dir).parent / "config" / "herkomst"


def record_collected(export_dir: Path, doel: str, provenance_dir: Path | None = None) -> None:
    """Writes the provenance record `status_ververs` writes after a scan of
    `doel`, for the manifest as it is NOW: a fixture export a test treats as
    collected by this server is recorded the way a real scan records it.
    Call it again after rewriting the manifest, as a new scan would."""
    import hashlib
    from datetime import UTC, datetime

    from nsmcp.export import record_provenance

    manifest_hash = hashlib.sha256((Path(export_dir) / "export-manifest.json").read_bytes()).hexdigest()
    record_provenance(
        provenance_dir or provenance_dir_for(export_dir), doel, manifest_hash, Path(export_dir), datetime.now(UTC)
    )


_BACKSLASH = "\\"

# The spellings Windows accepts for one and the same directory. A check that
# keeps two locations apart must see through every one of them: measured, a
# comparison on resolved text alone took the extended spelling of a map
# inside the export map for a map beside it.
PATH_SPELLINGS = (
    "gewoon",
    "hoofdletters",
    "omweg",
    "relatief",
    "uitgebreid",
    "uitgebreid-schuine-strepen",
    "uitgebreid-omweg",
    "apparaat",
    "volume-guid",
    "unc-uitgebreid",
    "beheershare",
)

# The spellings that only exist on Windows.
_WINDOWS_ONLY = frozenset(
    {
        "uitgebreid",
        "uitgebreid-schuine-strepen",
        "uitgebreid-omweg",
        "apparaat",
        "volume-guid",
        "unc-uitgebreid",
        "beheershare",
    }
)


def _volume_guid(path: Path) -> str | None:
    """`path` through the volume GUID of its own drive
    (`\\\\?\\Volume{...}\\...`), or None when this machine names no volume
    for that drive. Local, no share involved."""
    drive = path.drive
    if len(drive) != 2 or drive[1] != ":":
        return None
    import ctypes

    name = ctypes.create_unicode_buffer(64)
    if not ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(drive + _BACKSLASH, name, len(name)):
        return None
    return name.value + str(path)[3:]


def _administrative_share(path: Path) -> str | None:
    """`path` on the administrative share of its own local disk
    (`\\\\localhost\\<letter>$\\...`), or None when this machine does not
    offer that share for it - the share can be switched off, and a path
    without a drive letter has none."""
    drive = path.drive
    if len(drive) != 2 or drive[1] != ":":
        return None
    share = _BACKSLASH * 2 + "localhost" + _BACKSLASH + drive[0] + "$"
    try:
        reachable = Path(share + _BACKSLASH).is_dir()
    except OSError:
        reachable = False
    return share + str(path)[2:] if reachable else None


def spelled(path: Path, spelling: str) -> Path:
    """`path` (absolute) in one of PATH_SPELLINGS. `relatief` is relative to
    the current working directory - the caller changes to a directory above
    `path` first. Skips the test when this machine cannot write the spelling."""
    if spelling in _WINDOWS_ONLY and os.name != "nt":
        pytest.skip(f"spelling {spelling!r} bestaat alleen op Windows")
    text = str(path)
    extended = _BACKSLASH * 2 + "?" + _BACKSLASH
    if spelling == "gewoon":
        return path
    if spelling == "hoofdletters":
        return Path(text.upper() if os.name == "nt" else text)
    if spelling == "omweg":
        return path.parent / "elders" / ".." / path.name
    if spelling == "relatief":
        return Path(os.path.relpath(text))
    if spelling == "uitgebreid":
        return Path(extended + text)
    if spelling == "uitgebreid-schuine-strepen":
        return Path("//?/" + text.replace(_BACKSLASH, "/"))
    if spelling == "uitgebreid-omweg":
        return Path(extended + str(path.parent / "elders" / ".." / path.name))
    if spelling == "apparaat":
        return Path(_BACKSLASH * 2 + "." + _BACKSLASH + text)
    if spelling == "volume-guid":
        volume = _volume_guid(path)
        if volume is None:
            pytest.skip(f"deze machine noemt geen volume-GUID voor de schijf van {text!r}")
        return Path(volume)
    share = _administrative_share(path)
    if share is None:
        pytest.skip(f"de beheershare van de lokale schijf is op deze machine niet bereikbaar: {text!r}")
    if spelling == "beheershare":
        return Path(share)
    if spelling == "unc-uitgebreid":
        return Path(extended + "UNC" + _BACKSLASH + share[2:])
    raise ValueError(spelling)


def reparse_at(monkeypatch, *paths: Path, tag: int = 0xA0000003) -> None:
    """1.1 B: every `localpath` open of one of `paths` reports a reparse
    point with `tag` (a mount point by default), through the seam: the place
    stays an ordinary file or directory on disk, the walk sees what a junction
    in that place would show it. The stand-in for the `Path.lstat` patches
    of 1.0.3, now that no reader asks `lstat` any more."""
    from nsmcp import localpath

    native = localpath._native
    wanted = {os.path.normcase(str(Path(p).absolute()))[2:] for p in paths}
    where: dict[int, str] = {}
    real_open = native.NtCreateFile
    real_tag = native.query_attribute_tag

    def tracked_open(parent, name, *args, **kwargs):
        status, handle = real_open(parent, name, *args, **kwargs)
        if handle is not None:
            where[handle] = "" if parent is None else where.get(parent, "?") + _BACKSLASH + name
        return status, handle

    def reported_tag(handle):
        status, attributes, real = real_tag(handle)
        if os.path.normcase(where.get(handle, "?")) in wanted:
            return status, attributes | localpath.FILE_ATTRIBUTE_REPARSE_POINT, tag
        return status, attributes, real

    monkeypatch.setattr(native, "NtCreateFile", tracked_open)
    monkeypatch.setattr(native, "query_attribute_tag", reported_tag)


def directory_link(link: Path, target: Path) -> None:
    """Makes `link` a link to the directory `target`: a symbolic link where
    this machine allows one, else on Windows a junction (`mklink /J`, which
    needs no privilege). Skips the test when neither can be made."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    # By its full path (ComSpec): a bare `cmd` would be looked up in the
    # working directory first.
    shell = os.environ.get("ComSpec") if os.name == "nt" else None
    if shell:
        made = subprocess.run([shell, "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False)
        if made.returncode == 0 and link.is_dir():
            return
    pytest.skip(f"deze machine kan geen maplink maken: {str(link)!r}")


def maintenance_config(tmp_path: Path) -> MaintenanceConfig:
    ledger = tmp_path / "ledger"
    ledger.mkdir(parents=True, exist_ok=True)
    return MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=ledger,
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )


# ---------------------------------------------------------------------------
# 1.1 C: the anchor of the pseudonym table never touches the real HKCU store
# in a test. Every test gets its own in-memory store (`tablekey._registry`,
# the seam); the proofs on the real store use a unique key under
# HKCU\Software\GJK\netscaler-mcp\Test and remove it (tests/test_tablekey.py).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _table_anchor_in_memory(monkeypatch):
    from nsmcp import tablekey

    store = tablekey.MemoryRegistry()
    monkeypatch.setattr(tablekey, "_registry", store)
    return store


def table_place(table: Path):
    """The place (slot) of a pseudonym table, computed the way the product
    does: on a held chain of the table's directory (nothing is created)."""
    from nsmcp import localpath, tablekey

    table.parent.mkdir(parents=True, exist_ok=True)
    root = localpath.absolute_text(table.parent)
    with localpath.open_local(root, root=root, expect="dir") as held:
        return tablekey.place_of(table, root, held)


def write_signed_table(table: Path, rows) -> None:
    """A SIGNED form-2 table with exactly these (pseudonym, real name) rows,
    with its anchor and key - the semantic checks are NOT applied here, so a
    test can hand the product a well-signed table with a semantically broken
    row. `rows` is a dict or a list of pairs."""
    import secrets

    from nsmcp import tablekey

    pairs = list(rows.items()) if isinstance(rows, dict) else list(rows)
    where = table_place(table)
    tabel_id = secrets.token_hex(16)
    key = secrets.token_bytes(tablekey.KEY_BYTES)
    tablekey.key_path(table).write_bytes(tablekey.wrap_key(key, where.slot, tabel_id, 1))
    doc = tablekey.build_doc(key, where.slot, tabel_id, 1, pairs)
    table.write_bytes(tablekey.doc_bytes(doc))
    anchor = tablekey.Anchor(where.slot, tabel_id, 1, doc.aantal, doc.keten, "vastgelegd", None, ())
    tablekey._registry.write(where.slot, anchor.text())


def table_rows(table: Path) -> dict[str, str]:
    """PSEUDONYM -> REAL NAME as the form-2 file on disk carries it (read by
    the test, without verification)."""
    raw = json.loads(table.read_text(encoding="utf-8"))
    return {row["pseudoniem"]: row["naam"] for row in raw["rijen"]}


HKCU_TEST_BASE = "Software\\GJK\\netscaler-mcp\\Test"


@pytest.fixture
def hkcu_anchor(monkeypatch):
    """The REAL HKCU anchor store, under a unique key
    `HKCU\\Software\\GJK\\netscaler-mcp\\Test\\<uuid4>` that is removed
    afterwards (and proven gone). For the proofs that need the real store or
    a second process; every other test keeps the in-memory store."""
    import uuid
    import winreg

    from nsmcp import tablekey

    base = f"{HKCU_TEST_BASE}\\{uuid.uuid4()}"
    store = tablekey._WinRegistry(base)
    monkeypatch.setattr(tablekey, "_registry", store)
    yield store

    def remove(path: str) -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as key:
                while True:
                    try:
                        child = winreg.EnumKey(key, 0)
                    except OSError:
                        break
                    remove(f"{path}\\{child}")
        except FileNotFoundError:
            return
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)

    remove(base)
    with pytest.raises(FileNotFoundError):
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
