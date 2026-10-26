"""Shared harness for `onderhoud_upgrade_fase`: the NEP-runner, the code
channel stand-ins, and the server/call/propose helpers the tests around this
tool are built from.

A MODULE of its own, not a test module. `tests/
test_product_surface.py` pins the FASE GESTART answer byte-for-byte and used
to import this machinery straight out of `tests/test_upgrade_fase.py` - a
test importing another test, so a change to `_server`'s signature broke a
product-surface pin in a confusing place. The helpers live here now and both
test files import them from one, non-test source.

Like `conftest.py`, this resolves as a top-level module only because
`tests/` has no `__init__.py` and pytest's rootless (`prepend`) import puts
`tests/` itself on `sys.path`. A later `[tool.pytest.ini_options]`
`importmode` change can break that; this paragraph is the pointer to why.

Everything here runs against a NEP-runner: a small Python script that speaks
the same two-line contract `Invoke-GjkUpgradeFase.ps1` does (`[TARGET] ...` /
`[ACTIEID] ...` on every call, a `fase_gestart` ledger line on a confirmed
real run) without touching PowerShell, Posh-SSH or an appliance - the same
pattern `tests/test_handelen_zonder_code.py` already uses for the demo write
script.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import mcp.types as types
from conftest import knowledge_pin_for, provenance_dir_for, record_collected
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import mcp_server
from nsmcp.disclosure import Disclosure
from nsmcp.handelen import Allowlist, MaintenanceConfig
from nsmcp.upgrade import append_line

TARGET_NAME = "netscaler-02"
HOSTKEY = "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f"
DOELBUILD = "14.1-72.57"


# ---------------------------------------------------------------------------
# building blocks
# ---------------------------------------------------------------------------


def _export(tmp_path: Path) -> Path:
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-06T10:00:00.0000000Z",
                "resources": {},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    return m


def _anchor_target(export_dir: Path, doel: str, *, record: bool = True) -> None:
    """Writes `scan-doel.txt` the way a real scan leaves it: the target name,
    then the hash of THIS manifest - so the export describes `doel` until
    the manifest changes. Call it again after rewriting the manifest.

    A real scan also leaves the server's own provenance record, outside the
    export; so does this, unless `record=False` - an export that only CLAIMS
    to describe `doel`, the way a supplied one can."""
    digest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    (export_dir / "scan-doel.txt").write_text(f"{doel}\n{digest}\n", encoding="utf-8")
    if record:
        record_collected(export_dir, doel)


def _reanchor(export_dir: Path) -> None:
    """Binds an existing `scan-doel.txt` to the manifest as it is now; an
    export without one stays without one."""
    target_file = export_dir / "scan-doel.txt"
    if target_file.exists():
        _anchor_target(export_dir, target_file.read_text(encoding="utf-8").splitlines()[0])


def _knowledge(tmp_path: Path) -> Path:
    p = tmp_path / "kennis.json"
    # `cve` is REQUIRED (SECURITY 12): without it the reader refuses
    # the package and every answer says "Kennisbasis: ONBEKEND".
    p.write_text(json.dumps({"versie": "2026.09", "datum": "2026-09-06", "cve": []}), encoding="utf-8")
    return p


def _targets_file(tmp_path: Path, *, hostkey: str | None = HOSTKEY) -> Path:
    entry = {
        "naam": TARGET_NAME,
        "adres": "10.0.0.2",
        "credentialTarget": "GJK/Test/netscaler-02/nitro-write",
        "certificaat": "keten",
    }
    if hostkey is not None:
        entry["ssh_hostsleutel_vingerafdruk"] = hostkey
    p = tmp_path / "doelen.json"
    p.write_text(json.dumps({"doelen": [entry]}), encoding="utf-8")
    return p


FLOOR_BULLETINS = (("CTX696604", "72.61"), ("CTX696939", "73.32"))


def _with_floor(
    tmp_path: Path,
    *,
    version: str = "NetScaler NS14.1: Build 72.57.nc",
    bulletins: tuple[tuple[str, str], ...] = FLOOR_BULLETINS,
) -> None:
    """Gives the export and the knowledge package `_server()` wrote a floor
    to derive: a readable running build in the export and bulletins with a
    14.1 fix build in the package. The server reads both at call time, but
    it pins the package it was built with: pass `floor=` to `_server()` for
    a pinned package with a floor. Run after `_server()`, only the export's
    build may differ (the same bulletins write the same package)."""
    from conftest import seal_manifest

    export = tmp_path / "export"
    (export / "objects" / "nsversion.json").write_text(
        json.dumps({"errorcode": 0, "message": "Done", "nsversion": {"version": version}}), encoding="utf-8"
    )
    manifest_pad = export / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["resources"]["config/nsversion"] = {"status": "OK"}
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export)
    _reanchor(export)
    (tmp_path / "kennis.json").write_text(
        json.dumps(
            {
                "versie": "2026.09",
                "datum": "2026-09-06",
                "cve": [
                    {
                        "bulletin": naam,
                        "datum": "2026-06-30",
                        "getroffen": {"14.1": f"< {fix}"},
                        "fix": {"14.1": fix},
                        # 1.1: a bulletin names at least one CVE.
                        "cves": [
                            {"id": f"CVE-2026-{9001 + nummer}", "cvss": 5.0, "kern": "proef", "voorwaarde": "altijd"}
                        ],
                        "advies": "upgrade",
                        "extraStapNaUpgrade": "",
                    }
                    for nummer, (naam, fix) in enumerate(bulletins)
                ],
            }
        ),
        encoding="utf-8",
    )


def _argv_rows(ledgermap: Path) -> list[list[str]]:
    """Every argument list the NEP-runner received, in the order written."""
    rows: list[list[str]] = []
    for pad in sorted(ledgermap.glob("*.argv.json")):
        rows += [json.loads(regel) for regel in pad.read_text(encoding="utf-8").splitlines() if regel.strip()]
    return rows


def _firmwaremap(tmp_path: Path, *, doelbuild: str = DOELBUILD) -> Path:
    m = tmp_path / "firmware"
    m.mkdir(exist_ok=True)
    (m / f"build-{doelbuild}_nc_64.tgz").write_bytes(b"niet-een-echte-bundel")
    (m / f"build-{doelbuild}_nc_64.tgz.sha256").write_text("deadbeef", encoding="utf-8")
    return m


_NEP_RUNNER_TEMPLATE = '''\
"""NEP-runner: speaks Invoke-GjkUpgradeFase.ps1's own two-line contract
(scripts/README.md) without touching PowerShell, Posh-SSH or an appliance."""
import json
import sys
import time
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    argv = sys.argv[1:]
    args = {{}}
    flags = set()
    FLAGS = {{"-WatIs", "-DriftGeaccepteerd", "-OudeBuildbomenOpruimen", "-DoelbuildGeaccepteerd"}}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in FLAGS:
            flags.add(a)
            i += 1
            continue
        if a.startswith("-") and i + 1 < len(argv):
            args[a] = argv[i + 1]
            i += 2
            continue
        i += 1

    ledger = args.get("-Ledger", "")
    if ledger:
        argv_pad = ledger[:-6] + ".argv.json" if ledger.endswith(".jsonl") else ledger + ".argv.json"
        with open(argv_pad, "a", encoding="utf-8") as f:
            f.write(json.dumps(argv) + "\\n")

    doel = args.get("-Doel", "")
    adres = args.get("-Adres", "")
    fase = args.get("-Fase", "")
    run = args.get("-Run", "")
    doelbuild = args.get("-Doelbuild", "")
    opruim = ", oude buildbomen opruimen" if "-OudeBuildbomenOpruimen" in flags else ""
    print("[TARGET] " + doel + " (" + adres + ") - fase " + fase + " naar build " + doelbuild + opruim)
    if {write_actieid!r}:
        print("[ACTIEID] upgrade-" + fase + "-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))

    if "-WatIs" in flags:
        return 0

    actieid = args.get("-Actieid", "")
    if not actieid:
        print("[GEWEIGERD] -Actieid ontbreekt")
        return 1

    if {write_gestart!r}:
        bevestiger = args.get("-Bevestiger")
        regel = {{
            "tijd": _now(), "run": run, "doel": doel, "fase": fase,
            "gebeurtenis": "fase_gestart", "poort": [], "uitkomst": "gestart",
            "bewijs": "nep-runner", "actieid": actieid, "bevestiger": bevestiger,
            "gestart": _now(), "geeindigd": None, "doelbuild": doelbuild,
        }}
        with open(ledger, "a", encoding="utf-8") as f:
            f.write(json.dumps(regel) + "\\n")

    time.sleep({sleep_after_start_s!r})
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _nep_runner(
    tmp_path: Path,
    name: str = "nep_runner.py",
    *,
    write_gestart: bool = True,
    sleep_after_start_s: float = 0.0,
    write_actieid: bool = True,
) -> Path:
    pad = tmp_path / name
    pad.write_text(
        _NEP_RUNNER_TEMPLATE.format(
            write_gestart=write_gestart,
            sleep_after_start_s=sleep_after_start_s,
            write_actieid=write_actieid,
        ),
        encoding="utf-8",
    )
    return pad


class CodeSpy:
    """A non-identifying channel (mimics `venster`/`bestand`): no
    `bevestiger_for`, no `bevestiger` attribute.

    `mcp_server._upgrade_work()` asks a channel for `bevestiger_for` and
    for nothing else - the bare `.bevestiger` fallback this comment used to
    describe was removed (see
    `BareBevestigerAttributeSpy` below, which pins that a channel carrying
    only that attribute is refused). A channel of THIS shape can name no
    confirmer at all, and that IS the identity gap MUTATIEPROEF 8 proves
    this tool refuses on."""

    label = "venster"

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, tool, target, arguments, code, proposal_text, marker, section) -> None:
        self.calls.append(
            {
                "tool": tool,
                "target": target,
                "arguments": dict(arguments),
                "code": code,
                "proposal_text": proposal_text,
                "marker": marker,
                "section": section,
            }
        )

    @property
    def codes(self) -> list:
        return [c["code"] for c in self.calls]


class BareBevestigerAttributeSpy(CodeSpy):
    """Mimics a
    HYPOTHETICAL future presenter that carries a bare `.bevestiger` string
    attribute but no `bevestiger_for` method - exactly the shape the
    comment next to the identity gate in `mcp_server._upgrade_work()`
    warns against, and exactly the shape the code used to accept anyway
    (`getattr(code_presenter, "bevestiger", None)` as the fallback). No
    shipped channel has this shape today; this class exists to prove the
    gate refuses it rather than assume no future one ever will."""

    label = "toekomstig-kanaal"

    def __init__(self, bevestiger: str = "iemand-zonder-codebinding@voorbeeld.invalid") -> None:
        super().__init__()
        self.bevestiger = bevestiger


class IdentifyingCodeSpy(CodeSpy):
    """Mimics the `sso` channel: identifies the confirmer via
    `bevestiger_for(code)`, keyed on the code exactly the way
    `code_channel.SsoCodeChannel` is."""

    label = "sso"

    def __init__(self, bevestiger: str = "jan.de.beheerder@voorbeeld.invalid") -> None:
        super().__init__()
        self._bevestiger = bevestiger
        self._per_code: dict[str, str] = {}

    def __call__(self, tool, target, arguments, code, proposal_text, marker, section) -> None:
        super().__call__(tool, target, arguments, code, proposal_text, marker, section)
        self._per_code[code] = self._bevestiger

    def bevestiger_for(self, code: str) -> str | None:
        return self._per_code.pop(code, None)


def _server(
    tmp_path: Path,
    *,
    hostkey: str | None = HOSTKEY,
    code_presenter=None,
    soak_uren: int = 24,
    allow: bool = True,
    runner: Path | None = None,
    ledgermap: Path | None = None,
    firmwaremap: Path | None = None,
    actieregister: Path | None = None,
    disclosure: Disclosure = Disclosure.FULL,
    export_target: str | None = TARGET_NAME,
    floor: dict | None = None,
    pinned: bool = True,
) -> object:
    """A server for an upgrade of `TARGET_NAME`. Its export describes that
    same target, the way `status_ververs` leaves it; `export_target` names
    another target, or None for an export that records none.

    The configuration pins the knowledge package as it stands when the
    server is built. `floor` (the keyword arguments of `_with_floor`, `{}`
    for its defaults) gives the export and the package a floor BEFORE that,
    so the pinned package is the one with the floor. `pinned=False` builds
    the server without a pin, the way a configuration without `kennispin`
    does."""
    export_dir = _export(tmp_path)
    if export_target is not None:
        _anchor_target(export_dir, export_target)
    knowledge_path = _knowledge(tmp_path)
    if floor is not None:
        _with_floor(tmp_path, **floor)
    targets_path = _targets_file(tmp_path, hostkey=hostkey)
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# ongebruikt door onderhoud_upgrade_fase", encoding="utf-8")
    ledgermap = ledgermap or (tmp_path / "ledger")
    ledgermap.mkdir(parents=True, exist_ok=True)
    firmwaremap = firmwaremap if firmwaremap is not None else _firmwaremap(tmp_path)
    runner = runner or _nep_runner(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=runner,
        ledgermap=ledgermap,
        firmwaremap=firmwaremap,
        soak_uren=soak_uren,
        ssh_gebruiker="nsroot",
        actieregister=actieregister,
    )
    allowlist = Allowlist(per_target={TARGET_NAME: {"onderhoud_upgrade_fase": allow}})
    presenter = code_presenter if code_presenter is not None else IdentifyingCodeSpy()
    server = mcp_server.build_server(
        export_dir,
        knowledge_path,
        targets_path=targets_path,
        action_script=schrijf,
        fixture_dir=tmp_path,
        code_presenter=presenter,
        allowlist=allowlist,
        onderhoud=onderhoud,
        disclosure=disclosure,
        provenance_dir=provenance_dir_for(export_dir),
        **({"knowledge_pin": knowledge_pin_for(knowledge_path)} if pinned else {}),
    )
    server.code_spy = presenter
    server.onderhoud = onderhoud
    return server


def _text(r: types.CallToolResult) -> str:
    return " ".join(b.text for b in r.content if hasattr(b, "text"))


def _call(server, name, args):
    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-desktop", version="1.0")
        ) as client:
            return await client.call_tool(name, args)

    return asyncio.run(go())


def _propose(server, **args):
    r = _call(server, "onderhoud_upgrade_fase", args)
    assert not r.isError, _text(r)
    code = server.code_spy.codes[-1]
    return code, _text(r)


def _regel(
    *,
    run: str,
    doel: str = TARGET_NAME,
    fase: str,
    gebeurtenis: str,
    uitkomst: str,
    gestart: str | None = None,
    geeindigd: str | None = None,
    actieid: str = "a-1",
    bevestiger: str = "tester",
) -> dict:
    nu = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "tijd": nu,
        "run": run,
        "doel": doel,
        "fase": fase,
        "gebeurtenis": gebeurtenis,
        "poort": [],
        "uitkomst": uitkomst,
        "bewijs": "test-fixture",
        "actieid": actieid,
        "bevestiger": bevestiger,
        "gestart": gestart,
        "geeindigd": geeindigd,
    }


def _r0_gesloten(run: str, *, doelbuild: str | None = DOELBUILD, **velden) -> list[dict]:
    """A closed R0 of `run` the way the runner leaves it: the `fase_gestart`
    row carrying the target build R0 started with (the run binding of R1..R6
    reads exactly that field), then the closing `voormeting_vast` row.
    `doelbuild=None` leaves the field out - a start row from before the
    binding existed."""
    start = _regel(run=run, fase="R0", gebeurtenis="fase_gestart", uitkomst="gestart", **velden)
    if doelbuild is not None:
        start["doelbuild"] = doelbuild
    sluit = _regel(run=run, fase="R0", gebeurtenis="voormeting_vast", uitkomst="geslaagd", **velden)
    return [start, sluit]


SECOND_TARGET_NAME = "netscaler-03"


def _two_target_write_server(
    tmp_path: Path,
    *,
    open_target: str,
    open_phase: str = "R0",
    open_started: datetime | None = None,
    code_presenter=None,
    allow_on_open_target: bool = True,
) -> object:
    """A server with TWO targets, both allowed to run `onderhoud_backup_maken`
    (the simplest write tool - objectless, no NITRO-argument validation) -
    and `onderhoud` configured so the cross-tool gate has a
    ledger to consult. `open_target` carries an open phase in the ledger;
    the other target's ledger is clean."""
    export_dir = _export(tmp_path)
    knowledge_path = _knowledge(tmp_path)
    doelen = {
        "doelen": [
            {
                "naam": TARGET_NAME,
                "adres": "10.0.0.2",
                "credentialTarget": "GJK/Test/netscaler-02/nitro-write",
                "certificaat": "keten",
            },
            {
                "naam": SECOND_TARGET_NAME,
                "adres": "10.0.0.3",
                "credentialTarget": "GJK/Test/netscaler-03/nitro-write",
                "certificaat": "keten",
            },
        ]
    }
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps(doelen), encoding="utf-8")
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# ongebruikt: action_run vervangt dit", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    start_moment = open_started or datetime.now(UTC)
    open_row = _regel(
        run="open-run",
        doel=open_target,
        fase=open_phase,
        gebeurtenis="fase_gestart",
        uitkomst="gestart",
        gestart=start_moment.isoformat().replace("+00:00", "Z"),
    )
    open_row["tijd"] = start_moment.isoformat().replace("+00:00", "Z")
    append_line(ledgermap / "open-run.jsonl", open_row)
    onderhoud = MaintenanceConfig(
        runner=_nep_runner(tmp_path),
        ledgermap=ledgermap,
        firmwaremap=_firmwaremap(tmp_path),
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    allowlist = Allowlist(
        per_target={
            TARGET_NAME: {"onderhoud_backup_maken": allow_on_open_target},
            SECOND_TARGET_NAME: {"onderhoud_backup_maken": True},
        }
    )

    server_presenter = code_presenter if code_presenter is not None else CodeSpy()

    def spy_write_script(arguments, timeout_s):
        if "-WatIs" in arguments:
            return 0, "[OK] zou doen: een backup maken\n[TARGET] doel\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n", ""
        return 0, "[ACTIEID] id-1\n[TARGET] doel\n[EINDSTATUS] actie uitgevoerd en teruggelezen\n", ""

    server = mcp_server.build_server(
        export_dir,
        knowledge_path,
        targets_path=targets_path,
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=spy_write_script,
        code_presenter=server_presenter,
        allowlist=allowlist,
        onderhoud=onderhoud,
        provenance_dir=provenance_dir_for(export_dir),
    )
    server.ledgermap = ledgermap
    server.code_spy = server_presenter
    return server
