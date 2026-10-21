"""v1 reads exclusively from disk. This test proves that, instead of promising it.

Coverage runs through a REAL MCP session: `build_server()`, a real
initialize handshake, and all fourteen reading tools with REAL input (an
export with a real certificate and a real binding), also checking that a
real answer comes out - thirteen of them through one session below (was
ten/nine, stale since read tools were added one at a time until the
count reached fourteen), `status_ververs`
in its own test because it is the only one that would reach an appliance. An earlier version of this file called two functions on an EMPTY
directory; both returned on their first existence check (`pad.exists()`),
so all that was proven was that two early returns open no socket, while
README.md and docs/klant/SECURITY.md claimed "a test fails as soon as a socket
opens". If one of the tools fell back early onto an error path, this test
would - like the old one - prove nothing; that is why the content
assertions are stated explicitly.

ONE DOCUMENTED EXCEPTION: the event loop itself. On Windows,
`asyncio.run()` falls back to `ProactorEventLoop`, which creates its own
self-pipe at construction via `socket.socketpair()`
(asyncio/proactor_events.py, `_make_self_pipe`). That is Python's own
plumbing, not network traffic of this product. Measured directly:
`asyncio.run()` fully under the guard trips in `runners.py -> _lazy_init`,
before a single line of ours runs. The loop is therefore CREATED BEFORE the
guard is set (the `no_sockets` fixture depends on `loop`, so that order is
enforced and does not hang on pytest-internal fixture ordering) and the
guard covers everything that happens after. README.md and docs/klant/SECURITY.md name
this boundary literally.

RECONFIRMED, AND EXTENDED: this exception is not only about the
CONSTRUCTION of the self-pipe. `ProactorEventLoop` re-reads that self-pipe
on EVERY cross-thread wakeup (`call_soon_threadsafe`, used by
`asyncio.to_thread`/`run_in_executor` among others to report a worker
thread result to the loop) via `_loop_self_reading`
(asyncio/proactor_events.py), which in turn does
`isinstance(conn, socket.socket)` (asyncio/windows_events.py::recv) - on
the ALREADY EXISTING self-pipe object, so long AFTER the construction
above. That check needs a real CLASS. So this too remains an exception that
does not depend on this guard (no network traffic of this product), but the
guard must ensure that `socket.socket` REMAINS a `type` - otherwise that
`isinstance` check crashes and the self-pipe read operation hangs silently
broken instead of failing cleanly. See `no_sockets` below for how that is
solved (patch the constructor, not the class) and
`test_status_ververs_scan_opens_no_socket_in_this_process` for where this
first made a real difference.
"""

import asyncio
import hashlib
import json
import shutil
import socket
import subprocess
from datetime import date
from pathlib import Path

import mcp.types as types
import pytest
from conftest import expiry_text_today, maintenance_config, provenance_dir_for, record_collected, seal_manifest
from mcp.shared.memory import create_connected_server_and_client_session
from upgrade_fase_harness import _anchor_target

from nsmcp.export import load_export

# The seven writing tools, by name. Design par. 3.1: a READING tool is every
# registered tool that is NOT in this list - that is the definition, and
# "every tool in these chapters" was measurably untrue.
from nsmcp.handelen import WRITE_TOOLS as ALL_WRITE_TOOLS, Allowlist, MaintenanceConfig
from nsmcp.knowledge import load_knowledge
from nsmcp.mcp_server import DEFAULT_CHAPTERS, build_server, forget_identities
from nsmcp.retention import KEPT_SUFFIX
from nsmcp.upgrade import append_line

# The reading tools with a DOCUMENTED exception: they start a separate process
# that does go on the network, with the `doelen` credential. The server process
# itself still opens no socket. A third name here is a change of the design,
# not test maintenance (design par. 3.1 and par. 6): `status_update_preflight`
# is the second documented exception, alongside `status_ververs`.
WRITE_TOOLS = frozenset(ALL_WRITE_TOOLS)

NETWORK_EXCEPTIONS = frozenset({"status_ververs", "status_update_preflight"})

CERT = "wildcard_gjk"
VSERVER = "LB_VS_PORTAAL"

# The read tools the real-session test below actually CALLS, each with the real
# input it gets there. Module level on purpose: the documentation pin further
# down derives its "measured" set from THIS tuple instead of from
# `all_read_tools - {"status_ververs"}`. The difference matters - the second
# form is a restatement of the registration set, so a read tool registered in
# build_server() and written into the documents but never added to this loop
# would leave those documents claiming "worden aangeroepen" for a tool no
# session ever calls, with the pin green.
REAL_SESSION_READ_TOOL_CALLS = (
    ("certificaat_wat_verloopt_er", {"horizon_dagen": 90}),
    ("certificaat_wat_breekt_er", {"certnaam": CERT}),
    ("certificaat_wat_moet_ik_doen", {"certnaam": CERT}),
    ("status_overzicht", {}),
    ("status_namen", {}),
    ("status_doelen", {}),
    ("status_gezondheid", {}),
    ("status_cve_controle", {}),
    ("dienst_status", {"dienst": "bestaat_niet"}),
    ("dienst_keten", {"dienst": ""}),
    ("kennis_uitleg", {"begrip": "servicegroup"}),
    ("rapport_dekking", {}),
    ("ha_stand", {}),
    ("config_drift", {}),
    ("beveiliging_verstopte_regels", {}),
    ("beveiliging_tls_baseline", {}),
    ("beveiliging_beheervlak", {}),
    ("beveiliging_headers", {}),
    ("beveiliging_scorekaart", {}),
    ("status_update_advies", {}),
    ("onderhoud_upgrade_plan", {}),
    ("onderhoud_upgrade_stand", {}),
    ("rapport_na_upgrade", {}),
    # Compares the configured export against ITSELF: a real, existing
    # sibling directory (`_real_export()` names it "export", the export
    # root's own parent) without a second hand-built fixture - this tool
    # must not be called with two DIFFERENT real
    # directories here (a dedicated refusal test below covers the path
    # guard instead), and this loop's premise assertion (line ~387) forces
    # every REGISTERED reading tool to appear here regardless.
    ("rapport_vergelijk", {"mapA": "export", "mapB": "export"}),
    ("rapport_wat_is_er_veranderd", {}),
)


@pytest.fixture
def loop():
    """An event loop that ALREADY EXISTS before the socket guard is set.

    See the module docstring: on Windows, ProactorEventLoop creates a
    self-pipe with socket.socketpair() at construction. That is not part of
    what this product does, so it falls outside the measurement - and that
    is stated here, instead of silently weakening the guard.
    """
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture
def no_sockets(loop, monkeypatch):
    """Every entrance to the network in the socket module is refused.

    `socket.socket` is the constructor every Python socket passes through
    (including ssl.SSLSocket and socket.create_server). `socketpair`,
    `create_connection` and `getaddrinfo` are listed explicitly so that a
    stray name lookup or a socket pair stands out immediately instead of
    only at the next connection.

    Depends on `loop` so the event loop is guaranteed to exist before this
    guard (see the module docstring).

    `socket.socket` is NOT replaced as a CLASS by `refuse` below - only its
    `__init__` is refused. The guarantee this guard offers is "no socket is
    CONSTRUCTED", not "socket.socket stops being a class". The old form
    (`monkeypatch.setattr(socket, "socket", weiger)`) also met that
    guarantee, but had a side effect unrelated to this guard:
    `asyncio.ProactorEventLoop` (Windows, see `loop` above and the module
    docstring) re-reads its self-pipe on EVERY cross-thread wakeup via
    `_loop_self_reading` (asyncio/proactor_events.py), which does
    `isinstance(conn, socket.socket)` (asyncio/windows_events.py::recv) - a
    check that needs a real CLASS, not a function. With `socket.socket`
    replaced as a class, that `isinstance` check crashed as soon as a
    cross-thread wakeup was ever needed (`asyncio.to_thread`,
    `run_in_executor`, anything using `call_soon_threadsafe`) - silently
    (only logged through asyncio's default exception handler), leaving a
    PERMANENTLY broken self-pipe read operation: no failing assert, but an
    infinite hang. Encountered directly at `status_ververs` (async with
    `asyncio.to_thread(collect, ...)` inside - see mcp_server.py) through
    `test_status_ververs_scan_opens_no_socket_in_this_process` below, and
    reduced to its core in an isolated script without project code
    (`await asyncio.to_thread(lambda: 1 + 1)` on a fresh `ProactorEventLoop`
    after `socket.socket = some_function` gives the same `TypeError` in
    `_loop_self_reading`).

    By patching `socket.socket.__init__` instead, `socket.socket` stays a
    real `type` - the self-pipe's `isinstance` check keeps working as
    asyncio expects - while every NEW construction still lands on `refuse`
    immediately, including subclasses such as `ssl.SSLSocket` (which the
    old class replacement would have missed: a subclass runs through
    `super().__init__()` into the same, here patched,
    `socket.socket.__init__` - a replaced CLASS, by contrast, never touches
    a subclass instance, which stays on the old, unchanged class). This
    does not WEAKEN the guard - it makes it more precise:
    `test_the_guard_really_trips` below proves that a real
    `socket.socket()` call is still refused.

    `socketpair`, `create_connection` and `getaddrinfo` stay unchanged
    (bare module functions, not a class - no `isinstance` users in
    asyncio's self-pipe path are affected by them).
    """

    def refuse(*a, **kw):
        raise AssertionError("v1 mag geen socket openen")

    monkeypatch.setattr(socket.socket, "__init__", refuse)
    monkeypatch.setattr(socket, "socketpair", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _real_export(tmp_path: Path) -> Path:
    """An export with a REAL certificate and a REAL binding.

    Emphatically not an empty directory: on an empty directory all three
    tools return early on a read gap, and then this test proves exactly as
    little as the old version did.
    """
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir(parents=True)
    # FILE NAME/SHAPE: the REAL NSHC 1.0 collector writes
    # `objects/sslcertkey.json` (no "config_" prefix) and
    # `bindings/sslvserver_sslcertkey_binding.by-parent.json` in the
    # by-parent shape - see `tests/fixtures/lab-export-vpx-20260826/`.
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": CERT, "daystoexpiration": 9, "status": "Valid"}]}),
        encoding="utf-8",
    )
    # De OBJECTBRON van de parents. De echte collector schrijft die altijd
    # (`config/sslvserver` in het manifest, `objects/sslvserver.json` op
    # schijf); zonder die bron is de parentlijst van het bindingsbestand niet
    # te kruiscontroleren en meldt de motor daar terecht een leesgat over.
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": VSERVER}]}), encoding="utf-8"
    )
    raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [
                {
                    "parentName": VSERVER,
                    "outcome": "OK",
                    "data": {
                        "sslvserver_sslcertkey_binding": [
                            {"certkeyname": CERT, "vservername": VSERVER, "snicert": False, "ca": False}
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/sslcertkey": {"status": "OK"},
                    "config/sslvserver": {"status": "OK"},
                },
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        raw.encode("utf-8")
                    ).hexdigest()
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    return export_dir


def _real_knowledge(tmp_path: Path) -> Path:
    path = tmp_path / "kennis.json"
    path.write_text(json.dumps({"versie": "2026.08", "datum": "2026-08-16", "cve": []}), encoding="utf-8")
    return path


def test_reading_the_export_opens_no_socket(tmp_path, no_sockets):
    load_export(tmp_path)


def test_reading_the_knowledge_opens_no_socket(tmp_path, no_sockets):
    load_knowledge(tmp_path / "kennis.json", today=date(2026, 8, 19))


def test_reading_an_export_with_real_content_opens_no_socket(tmp_path, no_sockets):
    """The original two tests ran on an EMPTY directory and both returned
    on their first existence check. This one really does the whole read:
    manifest, object file, hash check and the binding file.
    """
    export_dir = _real_export(tmp_path)
    export = load_export(export_dir)
    certs, gap = export.objects("config/sslcertkey")
    assert gap is None and certs, "zonder echt gelezen objecten bewijst deze test niets"
    bindings, gap = export.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is None and bindings, "zonder echt gelezen bindingen bewijst deze test niets"


def test_reading_knowledge_with_a_real_package_opens_no_socket(tmp_path, no_sockets):
    knowledge = load_knowledge(_real_knowledge(tmp_path), today=date(2026, 8, 20))
    assert knowledge.missing is False, "zonder echt geladen kennispakket bewijst deze test niets"


def _scan_configuration(tmp_path: Path) -> tuple[Path, Path]:
    """A targets file and a collector script. Since security 19 a tool is only
    registered when the configuration it needs is there, and this guard has to
    measure the FULLY configured server - that is the one a customer runs, and
    it is the only one that carries the exception this file exists to bound.

    Neither file is executed here: `_run_powershell` is replaced by a stub in
    every test under this guard."""
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    collect_script = tmp_path / "verzamel.ps1"
    collect_script.write_text("# leeg; deze test voert niets uit", encoding="utf-8")
    return targets_path, collect_script


def _complete_server(tmp_path, export_dir, knowledge_path, *, writing=False):
    targets_path, collect_script = _scan_configuration(tmp_path)
    maintenance = maintenance_config(tmp_path)
    append_line(
        maintenance.ledgermap / "20260906T100000Z-lab.jsonl",
        {
            "tijd": "2026-09-06T10:00:00Z",
            "run": "20260906T100000Z-lab",
            "doel": "lab",
            "fase": "R0",
            "gebeurtenis": "fase_geslaagd",
            "uitkomst": "geslaagd",
            "poort": [],
            "bewijs": "synthetische registerfixture",
        },
    )
    return build_server(
        export_dir,
        knowledge_path,
        targets_path=targets_path,
        collect_script=collect_script,
        onderhoud=maintenance,
        action_script=collect_script if writing else None,
        fixture_dir=tmp_path if writing else None,
        code_presenter=(lambda *args: None) if writing else None,
        allowlist=Allowlist(per_target={"lab": {"onderhoud_upgrade_fase": True, "config_opslaan": True}}),
        # The test's configuration map, never beside or inside `export_dir`:
        # the shipped lab export is used in place and must stay untouched.
        provenance_dir=tmp_path / "config" / "herkomst",
    )


def test_build_server_opens_no_socket(tmp_path, no_sockets):
    """`build_server()` fell entirely outside the old coverage: it builds
    the FastMCP server, registers the reading tools and wraps their
    argument validation.

    Built WITH targets_path/collect_script - the
    shape start.py actually uses in production, and the shape under which
    a conditionally-registered read tool (status_ververs's own shape, and
    the shape status_update_preflight/B3 has too) would register. A
    server built without them - as this test did before this fix - can never see
    such a tool at all, so its exact-set assertion below would stay green
    even with one open a socket right past this guard.
    """
    # A COMPLETE scan configuration, because status_ververs only exists when
    # both halves are there (security 19) and this test must keep covering all
    # twelve reading tools. Neither file is opened here beyond load_targets()
    # reading the targets JSON - no socket either way.
    server = _complete_server(tmp_path, _real_export(tmp_path), _real_knowledge(tmp_path))
    # status_ververs, status_cve_controle and dienst_status count here too.
    # MEASURED by the guard in this whole file: that
    # tool's code path - everything in mcp_server.py/collect.py up to the
    # call of the runner - opens no socket in THIS process. That holds here
    # and in test_status_ververs_scan_opens_no_socket_in_this_process below,
    # both with `_run_powershell` replaced by a `run` stub; subprocess.run -
    # the only production line that ever touches an appliance - runs in
    # NONE of the tests under this guard.
    # REASONED, not measured: that the real scan (the PowerShell child
    # process collect.py starts in production, see the module docstring
    # there) also opens no socket in this process. That follows from the
    # process model, not from a measurement here: a monkeypatch on the
    # socket module of THIS Python process can never see the socket calls
    # of a child process anyway - measured or not.
    registered = {t.name for t in server._tool_manager.list_tools()}
    # The reading tools are DEFINED, not enumerated (design par. 6): everything
    # registered, minus the seven writing tools (WRITE_TOOLS), minus the
    # documented exceptions.
    # A new reading tool is covered by this guard the day it is registered,
    # without anyone remembering to add it here.
    reading = registered - WRITE_TOOLS - NETWORK_EXCEPTIONS
    assert reading, "the reading set is empty - this guard would prove nothing"
    assert NETWORK_EXCEPTIONS <= registered, (
        "the documented exception is not registered on this server; a scan"
        " configuration is needed for it (security 19), and dropping the name"
        " here would remove the ONE tool that touches an appliance from the"
        " coverage of this guard"
    )
    assert reading == {name for name, _ in REAL_SESSION_READ_TOOL_CALLS}


def test_the_reading_tools_open_no_socket_through_a_real_session(tmp_path, loop, no_sockets):
    """The core: the full SDK path under the guard.

    A real in-memory MCP session with a real initialize handshake, and all
    reading tools with real input. The assertions on the content are not
    decoration: without them this test would pass just as well if every
    tool fell straight onto an error path - exactly the gap the old version
    had.
    """
    forget_identities()
    export_dir = _real_export(tmp_path)
    # The export describes the one configured target, as a scan of it leaves
    # it: `rapport_na_upgrade` answers only from an export of the target
    # whose ledger it reads, also without `doel`.
    _anchor_target(export_dir, "lab")
    server = _complete_server(tmp_path, export_dir, _real_knowledge(tmp_path))

    async def scenario():
        answers = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for name, args in REAL_SESSION_READ_TOOL_CALLS:
                r = await client.call_tool(name, args)
                answers[name] = (
                    r.isError,
                    " ".join(b.text for b in r.content if hasattr(b, "text")),
                )
        return answers

    answers = loop.run_until_complete(scenario())

    for name, (error, text) in answers.items():
        assert error is False, f"{name} gaf een fout terug: {text}"

    assert expiry_text_today(9, "2026-08-20") in answers["certificaat_wat_verloopt_er"][1]
    assert VSERVER in answers["certificaat_wat_breekt_er"][1]
    assert "Terugleescontrole" in answers["certificaat_wat_moet_ik_doen"][1]
    assert "hoe staat de netscaler ervoor" in answers["status_overzicht"][1].lower()
    assert "welke namen kent deze netscaler" in answers["status_namen"][1].lower()
    # Read from the configuration, the manifest and the ledger on disk: the
    # configured target with its address, never its credential target.
    assert "- lab: adres 10.0.0.10;" in answers["status_doelen"][1]
    assert "gjk/netscaler/lab/readonly" not in answers["status_doelen"][1].lower()
    assert "wat stond er down op het moment van de scan" in answers["status_gezondheid"][1].lower()
    assert "kennispakket draagt geen CVE-regels" in answers["status_cve_controle"][1]
    assert "niet vast te stellen" in answers["dienst_status"][1]
    assert "waar hangt deze dienst aan" in answers["dienst_keten"][1].lower()
    assert "staat niet in het kennispakket" in answers["kennis_uitleg"][1]
    assert "hoe compleet is dit antwoord" in answers["rapport_dekking"][1].lower()
    # The bare export of `_real_export()` carries no config/hanode, no running
    # config and no saved config, so this answer rightly reports read gaps on
    # all four dimensions. That is not a failure - the assertion here proves
    # the tool ANSWERS; tests/test_ha.py proves WHAT it answers.
    assert "mag ik hier op de primary wijzigen" in answers["ha_stand"][1].lower()
    # Same bare export: no running and no saved config, so a read gap -
    # `onbevestigd`, never "geen drift".
    assert "- config-drift: onbevestigd [niet vastgesteld]" in answers["config_drift"][1]
    assert "wat zit hier verstopt" in answers["beveiliging_verstopte_regels"][1].lower()
    assert "welke tls-instellingen wijken af" in answers["beveiliging_tls_baseline"][1].lower()
    assert "staat het beheer van deze doos open" in answers["beveiliging_beheervlak"][1].lower()
    assert "staan de security-headers er echt op" in answers["beveiliging_headers"][1].lower()
    # `_real_export()`'s manifest names only config/sslcertkey and
    # config/sslvserver - six of `compare.COMPARED`'s seven resources
    # (everything except sslcertkey) are therefore ONTBREEKT on BOTH sides
    # of this self-comparison, a genuine equal failure (C1/C2): the
    # configuration/state blocks correctly refuse to say "geen
    # [vastgesteld]" over resources this export never even claims to carry.
    assert "- configuratieverschillen: geen [vastgesteld]" not in answers["rapport_vergelijk"][1]
    assert "- configuratieverschillen: niet vastgesteld [niet vastgesteld]" in answers["rapport_vergelijk"][1]
    assert "niet in de vergelijking meegenomen" in answers["rapport_vergelijk"][1]
    # No `.bewaard-` sibling sits next to `_real_export()` in this test -
    # the "a real previous export exists" branch is proven by the
    # dedicated equivalence test below instead.
    assert "niets om mee te vergelijken" in answers["rapport_wat_is_er_veranderd"][1]


# Dutch spelled-out numbers, small and cardinal/ordinal only - just enough to
# cover the tool counts docs/klant/SECURITY.md and docs/klant/HANDLEIDING.md
# state today plus a little headroom for the next tool or two.
_DUTCH_CARDINAL = {
    4: "vier",
    5: "vijf",
    6: "zes",
    7: "zeven",
    8: "acht",
    9: "negen",
    10: "tien",
    11: "elf",
    12: "twaalf",
    13: "dertien",
    14: "veertien",
    15: "vijftien",
    16: "zestien",
    17: "zeventien",
    18: "achttien",
    19: "negentien",
    20: "twintig",
}
_DUTCH_ORDINAL = {
    7: "zevende",
    8: "achtste",
    9: "negende",
    10: "tiende",
    11: "elfde",
    12: "twaalfde",
    13: "dertiende",
    14: "veertiende",
    15: "vijftiende",
    16: "zestiende",
    17: "zeventiende",
}
# The same range for README.md, which carries the same claims in English.
_ENGLISH_CARDINAL = {
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
    20: "twenty",
}
_ENGLISH_ORDINAL = {
    7: "seventh",
    8: "eighth",
    9: "ninth",
    10: "tenth",
    11: "eleventh",
    12: "twelfth",
    13: "thirteenth",
    14: "fourteenth",
    15: "fifteenth",
    16: "sixteenth",
    17: "seventeenth",
}


def _enumeration_passage(path: Path, opening: str, closing: str) -> str:
    """The one passage of `path` that ENUMERATES the tools, whitespace normalized.

    Tool names belong asserted against this slice, not against the whole
    file. `status_ververs` alone occurs six more times in the prose of
    docs/klant/SECURITY.md, so once a tool earns prose mentions of its own, a
    name deleted from the enumeration itself would stay invisible in a
    whole-file search. Each document's closing marker is therefore placed
    BEFORE any sentence that repeats the same names outside the enumeration.
    """
    text = " ".join(path.read_text(encoding="utf-8").split())
    start = text.find(opening)
    assert start != -1, f"{path.name}: enumeration does not open with {opening!r}"
    start += len(opening)
    end = text.find(closing, start)
    assert end != -1, f"{path.name}: enumeration does not close with {closing!r}"
    return text[start:end]


def test_the_documents_that_enumerate_the_tools_match_measured_reality(tmp_path):
    server = _complete_server(tmp_path, _real_export(tmp_path), _real_knowledge(tmp_path), writing=True)
    all_tools = {t.name for t in server._tool_manager.list_tools()}
    reading = all_tools - WRITE_TOOLS
    measured = {name for name, _ in REAL_SESSION_READ_TOOL_CALLS}
    assert all_tools & WRITE_TOOLS == WRITE_TOOLS
    assert reading - NETWORK_EXCEPTIONS == measured
    # 14-9-2026: `rapport_wat_is_er_veranderd` (a thin shell on the same
    # comparison engine `rapport_vergelijk` uses) on the release: 31 tools,
    # 25 reading, 23 measured under the guard (two exceptions). The `config`
    # chapter adds `config_drift` (reading) and config_opslaan (writing): 33
    # tools, 26 reading, 24 measured, 7 writing, nine chapters. `status_doelen`
    # (reading, always registered) makes it 34 tools, 27 reading, 25 measured.
    assert len(all_tools) == 34 and len(reading) == 27 and len(measured) == 25
    assert len(all_tools & WRITE_TOOLS) == 7
    assert len(DEFAULT_CHAPTERS) == 9
    root = Path(__file__).resolve().parent.parent
    windows = (
        (root / "README.md", "## The thirty-four tools", "## A read gap is an outcome", all_tools),
        (root / "docs/klant/HANDLEIDING.md", "## Wat is dit", "## Installatie", all_tools),
        (
            root / "docs/klant/SECURITY.md",
            "### De grens van de socketgarantie",
            "## Hoe de voordeur zich verdedigt",
            measured,
        ),
    )
    for path, opening, closing, expected in windows:
        passage = _enumeration_passage(path, opening, closing)
        for name in expected:
            assert "`" + name in passage, f"{path.name}: {name} ontbreekt in de opsomming"
    for path in [root / "README.md", root / "docs/klant/HANDLEIDING.md", root / "docs/klant/SECURITY.md"]:
        text = path.read_text(encoding="utf-8")
        assert "34" in text and "27" in text and "7" in text
        assert "status_ververs" in text and "status_update_preflight" in text


def test_maintenance_tools_require_explicit_configuration(tmp_path):
    plain = build_server(_real_export(tmp_path), _real_knowledge(tmp_path))
    assert not any(t.name.startswith("onderhoud_") for t in plain._tool_manager.list_tools())


def test_the_guard_really_trips(loop, no_sockets):
    """Counter-probe on the guard itself. Without this test, a monkeypatch
    that silently stops tripping (a renamed attribute, a different socket
    module) would leave all tests above green - and then the whole file
    proves nothing any more. All four guarded entrances are touched.
    """
    for entry in (
        lambda: socket.socket(),
        lambda: socket.socketpair(),
        lambda: socket.create_connection(("127.0.0.1", 9)),
        lambda: socket.getaddrinfo("localhost", 80),
    ):
        with pytest.raises(AssertionError, match="geen socket openen"):
            entry()


def test_status_ververs_scan_opens_no_socket_in_this_process(tmp_path, loop, no_sockets):
    """`status_ververs` is the only tool that ever touches an appliance -
    and it does not do so itself: collect.collect() starts the NSHC
    collector script as a separate PowerShell subprocess and waits for the
    result (see the module docstring of collect.py). This test deliberately
    uses a CONFIGURED target with a `run` that simulates a successful scan
    - not the bare "geen doel ingesteld" early return - so the whole scan
    path really runs under the guard: creating the lock file, creating the
    work directory, the manifest check, the swap. Should a later change
    ever let the scan talk to the appliance directly IN-PROCESS (instead of
    across the subprocess boundary), that would be a socket call in this
    process and this test would break on it immediately - which is why it
    belongs here, under the same guard as the other tests in this file,
    instead of as a loose assumption in a comment line.
    """
    forget_identities()
    script = tmp_path / "collector.ps1"
    script.write_text("# leeg; draai() neemt het over in de test", encoding="utf-8")
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def successful_scan(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "objects").mkdir(parents=True, exist_ok=True)
        (out / "bindings").mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "manifestVersion": "1.1",
                    "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                    "resources": {"config/sslcertkey": {"status": "EMPTY"}},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        seal_manifest(out)
        return 0, ""

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        targets_path=targets_path,
        collect_script=script,
        run=successful_scan,
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_ververs", {"doelnaam": "lab"})

    result = loop.run_until_complete(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "is gelukt" in text.lower(), text


# ---------------------------------------------------------------------------
# THE SAME GUARANTEE, ON THE REAL EXPORT
# WITH REAL CVE RULES.
#
# The test above runs on a hand-built export with a knowledge package without
# CVE rules, so three of the twelve tools THIS loop calls return early on a
# read gap or on "geen CVE-regels": `status_cve_controle`, `dienst_status`
# and `status_overzicht` never reach their readers there. This one closes
# that gap for those twelve: the REAL collector export and the REAL
# bulletins, so every tool this loop calls does its whole read under the
# same guard.
#
# This loop used to be a SECOND, hand-written 7-tool
# list, written precisely to stop tools "falling early onto an error path"
# - and none of the five tool-adding changes since extended it. Measured on
# the guarded tmp export of the test above (not this one):
# beveiliging_verstopte_regels gave 0 geraakt/2 niet geraakt/27 niet
# beoordeeld (93% of the rule engine's read path never ran there),
# beveiliging_tls_baseline's one vserver graded NIET BEOORDEELD, ha_stand's
# four dimensions were all unconfirmed, and status_namen's six family
# readers were all unassessed - the five newest tools were never exercised
# on data that lets them actually establish anything, under this file's own
# socket guard. Fixed by deriving the tool NAMES from
# REAL_SESSION_READ_TOOL_CALLS (so a future read tool added to that master
# list and forgotten here fails LOUD, on the premise assertion below,
# instead of silently staying untested) and keeping this file's own
# LIVE-export-appropriate arguments next to it.
# ---------------------------------------------------------------------------

LIVE_EXPORT = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
LIVE_CERT = "CERT-009"

# The argument this file's own REAL export needs per tool - REAL_SESSION_READ_TOOL_CALLS
# above carries the args for the OTHER (hand-built) export instead, so the
# two cannot simply share one args mapping; only the tool NAME SET must
# match (see the premise assertion in the test below).
_LIVE_ARGS = {
    "certificaat_wat_verloopt_er": {"horizon_dagen": 900},
    "certificaat_wat_breekt_er": {"certnaam": LIVE_CERT},
    "certificaat_wat_moet_ik_doen": {"certnaam": LIVE_CERT},
    "status_overzicht": {},
    "status_namen": {},
    "status_doelen": {},
    "status_gezondheid": {},
    "status_cve_controle": {},
    "dienst_status": {"dienst": "gjkdemo_sg_proefdienst"},
    "dienst_keten": {"dienst": ""},
    "kennis_uitleg": {"begrip": "servicegroup"},
    "rapport_dekking": {},
    "ha_stand": {},
    "config_drift": {},
    "beveiliging_verstopte_regels": {},
    "beveiliging_tls_baseline": {},
    "beveiliging_beheervlak": {},
    "beveiliging_headers": {},
    "beveiliging_scorekaart": {},
    "status_update_advies": {},
    "onderhoud_upgrade_plan": {},
    "onderhoud_upgrade_stand": {},
    "rapport_na_upgrade": {},
    # The live export compared against itself - a real sibling directory
    # name (LIVE_EXPORT.name), no second fixture needed.
    "rapport_vergelijk": {"mapA": LIVE_EXPORT.name, "mapB": LIVE_EXPORT.name},
    # No `.bewaard-` sibling sits next to LIVE_EXPORT.
    "rapport_wat_is_er_veranderd": {},
}


def _live_knowledge(tmp_path: Path) -> Path:
    """The real bulletins, out of the one place this repository keeps them."""
    from test_cve import ECHTE_BULLETINS

    path = tmp_path / "kennis-echt.json"
    path.write_text(
        json.dumps(
            {
                "versie": "2026.09",
                "datum": "2026-09-02",
                "cve": list(ECHTE_BULLETINS),
                "begrippen": {"servicegroup": "Een groep servers achter een dienst."},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_the_reading_tools_on_the_REAL_export_open_no_socket(tmp_path, loop, no_sockets):
    tool_names = tuple(name for name, _ in REAL_SESSION_READ_TOOL_CALLS)
    # PREMISE: this loop's own argument mapping really covers exactly the
    # same tool set as the master list - not more, not fewer. A read tool
    # added to REAL_SESSION_READ_TOOL_CALLS without a matching entry here
    # fails HERE, loudly, instead of silently never being called under
    # this guard.
    assert set(_LIVE_ARGS) == set(tool_names)

    forget_identities()
    # The shipped lab export as this server's own scan of `lab`, recorded in
    # the test's configuration map (the fixture itself is never written).
    record_collected(LIVE_EXPORT, "lab", tmp_path / "config" / "herkomst")
    server = _complete_server(tmp_path, LIVE_EXPORT, _live_knowledge(tmp_path))

    async def scenario():
        answers = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for name in tool_names:
                r = await client.call_tool(name, _LIVE_ARGS[name])
                answers[name] = (
                    r.isError,
                    " ".join(b.text for b in r.content if hasattr(b, "text")),
                )
        return answers

    answers = loop.run_until_complete(scenario())
    for name, (error, text) in answers.items():
        assert error is False, f"{name} gaf een fout terug: {text}"

    # SUBSTANTIVE answers, per tool - without these the test would pass just
    # as well on twelve error paths, which is exactly what this guarantee
    # measures (and what the five newest tools confirm again, below).
    assert LIVE_CERT in answers["certificaat_wat_verloopt_er"][1]
    assert LIVE_CERT in answers["certificaat_wat_breekt_er"][1]
    # On this export the impact of that certificate is not established, and
    # the tool says so rather than proposing a change - a real answer out of
    # a real read, which is what this test measures.
    assert "geen wijzigingsvoorstel zolang de impact niet vaststaat" in (answers["certificaat_wat_moet_ik_doen"][1])
    assert "build: 14.1-72.57" in answers["status_overzicht"][1]
    assert "2 geraakt, 5 niet geraakt, 1 niet vastgesteld" in answers["status_cve_controle"][1]
    assert "config/lbvserver: 0 virtuele servers" in answers["dienst_status"][1]
    assert "Een groep servers" in answers["kennis_uitleg"][1]
    # The five newest tools, each with a finding that could only come
    # from a REAL, successful read of this export - not from an early
    # error path or an unassessed dimension.
    assert "Gateway-vservers: 2 namen - VSRV-002, VSRV-003 [vastgesteld]" in (answers["status_namen"][1])
    # The live export records `lab` as its target, and the ledger of
    # `_complete_server()` carries one closed R0 for it.
    assert (
        "- lab: adres 10.0.0.10; export van 2026-08-26, " in answers["status_doelen"][1]
        and "laatste onderhoudsrun 20260906T100000Z-lab, laatste regel R0 geslaagd om 2026-09-06T10:00:00Z"
        in answers["status_doelen"][1]
    ), answers["status_doelen"][1]
    assert (
        "- dekking: gedeeltelijk [vastgesteld]\n"
        "    bewijs: export-manifest.json: 58 bronnen - 29 OK, 24 LEEG, 1 MISLUKT, 4 OPTIONEEL AFWEZIG"
    ) in answers["rapport_dekking"][1]
    # NSHC's applicability word on a standalone appliance, not
    # a state word. `uit` confirmed a role distribution that does not
    # exist here.
    assert "- rolverdeling: niet van toepassing [vastgesteld]" in (answers["ha_stand"][1])
    # The header lines and the closing `Done` are not configuration
    # (nsmcp/config_drift.py); what is left compares equal on this export,
    # but its headers say it changed after the last save and ten lines per
    # side carry a value the collector withheld - not comparable, so the
    # verdict is not established, in both tools alike.
    assert "- config-drift: onbevestigd [niet vastgesteld]" in answers["ha_stand"][1]
    assert "- config-drift: onbevestigd [niet vastgesteld]" in answers["config_drift"][1]
    assert "10 regels per kant dragen een waarde die de verzamelaar al achterhield" in answers["config_drift"][1]
    assert "de inhoud is gelijk" not in answers["config_drift"][1]
    # Measured: 7/20/2, not the branch's 7/22/0. `config/lbmonitor` is the
    # one OK resource in this REAL manifest whose `payloadSha256` the
    # collector left empty, so the hash gate refuses it and the two rules
    # that read it come out `niet beoordeeld`. That is the truth about this
    # export; see NOT_ASSESSED_ON_THE_REAL_EXPORT in tests/test_hidden_rules.py
    # for the full measurement and docs/klant/OPENSTAANDE-METINGEN.md for the
    # open collector work.
    assert ("- verstopte regels: 29 regels - 7 geraakt, 20 niet geraakt, 2 niet beoordeeld") in answers[
        "beveiliging_verstopte_regels"
    ][1]
    assert "- blootstelling: FAIL [vastgesteld]" in answers["beveiliging_beheervlak"][1]
    assert "- Strict-Transport-Security: aanwezig en gebonden [vastgesteld]" in (answers["beveiliging_headers"][1])
    assert "- VSRV-003: niet vastgesteld [niet vastgesteld]" in answers["dienst_keten"][1]
    assert "- storing: geen object DOWN gezien [vastgesteld]" in answers["status_gezondheid"][1]
    assert "- Gateway-vservers: 2 gemeten, 0 DOWN [vastgesteld]" in answers["status_gezondheid"][1]
    # NSHC's letter (C 64), with the marker this product owes
    # on a cipher group whose members were never read.
    assert "- VSRV-003: C (score 64) [niet vastgesteld]" in (answers["beveiliging_tls_baseline"][1])
    # The live export compared against ITSELF: identical data cannot differ
    # from itself on configuratie/stand - including `port` and
    # `publickeysize`, JSON ints on this REAL NITRO export (measured: a
    # plain int is a readable, comparable value, not an unclear shape, so
    # this self-comparison establishes equality there too instead of
    # reporting NOT VASTGESTELD). Coverage is a different story: C1 -
    # `config/lbmonitor` is MISLUKT on this real export (empty
    # payloadSha256, see OPENSTAANDE-METINGEN.md), equally unreadable on
    # both "sides" of the self-comparison, so dekkingsverschillen correctly
    # refuses "geen [vastgesteld]" too instead of silently agreeing with
    # itself about a source neither side ever actually read.
    assert "- configuratieverschillen: geen [vastgesteld]" in answers["rapport_vergelijk"][1]
    assert "- standverschillen: geen [vastgesteld]" in answers["rapport_vergelijk"][1]
    assert "- dekkingsverschillen: geen [vastgesteld]" not in answers["rapport_vergelijk"][1]
    assert "- dekkingsverschillen: niet vastgesteld [niet vastgesteld]" in answers["rapport_vergelijk"][1]
    assert "config/lbmonitor: A: MISLUKT, B: MISLUKT" in answers["rapport_vergelijk"][1]
    # `_real_export()`/`_complete_server()` never leave a `.bewaard-`
    # sibling next to the export in this test, so this always hits the
    # "nothing kept" branch - the OTHER branch (a real previous export) is
    # proven by the dedicated equivalence test below instead.
    assert "niets om mee te vergelijken" in answers["rapport_wat_is_er_veranderd"][1]


NO_SOCKET_EXCEPTIONS = ("status_ververs", "status_update_preflight")


def test_the_exception_list_holds_exactly_these_two_names():
    """Pinned as a value rather than as a comment: a third exception has to be
    a deliberate edit of this line, argued in the design, and never a quiet
    addition somewhere in mcp_server.py."""
    assert NO_SOCKET_EXCEPTIONS == ("status_ververs", "status_update_preflight")


def test_every_exception_is_really_a_registered_tool(tmp_path):
    """A name on this list that no longer exists would make the list a
    decoration - it would keep passing while covering nothing."""
    server = _complete_server(tmp_path, _real_export(tmp_path), _real_knowledge(tmp_path))
    registered = {t.name for t in server._tool_manager.list_tools()}
    for name in NO_SOCKET_EXCEPTIONS:
        assert name in registered


def test_status_update_preflight_opens_no_socket_in_this_process(tmp_path, loop, no_sockets):
    """The SECOND documented exception, measured to exactly its boundary.

    Deliberately with a CONFIGURED target and a `run` stub - not the bare
    "geen doel ingesteld" early return - so the whole live-read path really
    runs under the guard: building the argument list, creating and removing
    the temporary output directory, and reading the result back through
    `load_export`. The one thing that is NOT exercised is `subprocess.Popen`
    itself, and that is the point of the boundary: the appliance is reached by
    a SEPARATE PROCESS, so no socket of it can exist in this one.

    The two assertions at the end are what make this a measurement instead of
    a promise: the tool really started that separate process (the stub was
    called, with `-OnlyResources stat/system` on the argument list), and the
    number that came back really reached the answer.
    """
    forget_identities()
    script = tmp_path / "collector.ps1"
    script.write_text("# leeg; draai() neemt het over in de test", encoding="utf-8")
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    started = []

    def live_read(arguments, timeout_s):
        """The separate process, stubbed. Everything up to here is measured."""
        started.append(list(arguments))
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "objects").mkdir(parents=True, exist_ok=True)
        (out / "objects" / "system.json").write_text(json.dumps({"system": {"disk1avail": "12345"}}), encoding="utf-8")
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "manifestVersion": "1.1",
                    "collectedAtUtc": "2026-09-05T10:00:00.0000000Z",
                    "resources": {"stat/system": {"status": "OK", "propertyName": "system"}},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        seal_manifest(out)
        return 0, ""

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        targets_path=targets_path,
        collect_script=script,
        run=live_read,
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_update_preflight", {})

    result = loop.run_until_complete(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert started, "de tool moet het aparte proces echt gestart hebben"
    assert started[0][-2:] == ["-OnlyResources", "stat/system"]
    assert "12345 MB" in text, text
    assert "live gelezen" in text


def test_the_preflight_never_lets_the_credential_target_reach_the_answer(tmp_path, loop, no_sockets):
    """A failed live read travels into the answer as a read gap. The scrub of
    a failed scan applies there just as it does to `status_ververs`."""
    forget_identities()
    script = tmp_path / "collector.ps1"
    script.write_text("# leeg", encoding="utf-8")
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def failing_read(arguments, timeout_s):
        return 1, "kan niet inloggen op 10.0.0.10 met gjk/netscaler/lab/readonly"

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        targets_path=targets_path,
        collect_script=script,
        run=failing_read,
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_update_preflight", {})

    result = loop.run_until_complete(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "gjk/netscaler/lab/readonly" not in text
    assert "10.0.0.10" not in text
    assert "niet beoordeeld" in text


# ---------------------------------------------------------------------------
# Check 8 over SSH. The route is chosen on CONFIGURATION: SSH when `onderhoud`
# is configured and the target carries a pinned host key, the collector
# otherwise. A failed SSH read is a read gap with its reason - never a second
# attempt through the collector. The read script is a separate PowerShell
# process (Invoke-GjkLiveMeting.ps1); `live_run` stands in for it here, so the
# whole route up to the process start runs under the socket guard.
# ---------------------------------------------------------------------------

_PINNED_HOSTKEY = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def _preflight_targets(tmp_path: Path, *, pinned: bool) -> Path:
    doel = {
        "naam": "lab",
        "adres": "10.0.0.10",
        "credentialTarget": "gjk/netscaler/lab/readonly",
        "certificaat": "keten",
    }
    if pinned:
        doel["ssh_hostsleutel_vingerafdruk"] = _PINNED_HOSTKEY
    pad = tmp_path / "doelen.json"
    pad.write_text(json.dumps({"doelen": [doel]}), encoding="utf-8")
    return pad


def _preflight_over_ssh(tmp_path, loop, *, pinned=True, onderhoud=True, live=None, script_present=True):
    forget_identities()
    collector = tmp_path / "collector.ps1"
    collector.write_text("# leeg; de stub neemt het over", encoding="utf-8")
    maintenance = maintenance_config(tmp_path) if onderhoud else None
    if maintenance is not None and script_present:
        (Path(maintenance.runner).parent / "Invoke-GjkLiveMeting.ps1").write_text("# stub", encoding="ascii")
    collector_calls: list = []
    ssh_calls: list = []

    def collector_run(arguments, timeout_s):
        collector_calls.append(list(arguments))
        return 1, "de collector mag hier niet draaien"

    def ssh_run(arguments, timeout_s):
        ssh_calls.append((list(arguments), timeout_s))
        if live is not None:
            return live(arguments, timeout_s)
        return 0, "[OK] SSH-sessie geopend\n[VRIJ_MB] 12345\n[EINDSTATUS] GEMETEN: vrije ruimte op /var gelezen\n", ""

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        targets_path=_preflight_targets(tmp_path, pinned=pinned),
        collect_script=collector,
        run=collector_run,
        onderhoud=maintenance,
        live_run=ssh_run,
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_update_preflight", {})

    result = loop.run_until_complete(scenario())
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    return result, text, collector_calls, ssh_calls


def test_status_update_preflight_reads_free_space_over_ssh_when_onderhoud_and_a_pin_are_there(
    tmp_path, loop, no_sockets
):
    result, text, collector_calls, ssh_calls = _preflight_over_ssh(tmp_path, loop)
    assert result.isError is False, text
    assert len(ssh_calls) == 1
    arguments, timeout_s = ssh_calls[0]
    assert timeout_s == 120
    assert arguments[arguments.index("-File") + 1].endswith("Invoke-GjkLiveMeting.ps1")
    assert arguments[arguments.index("-Meting") + 1] == "vrije-ruimte"
    assert (
        arguments[arguments.index("-HostsleutelVingerafdruk") + 1] == "aa:bb:cc:dd:ee:ff:0:11:22:33:44:55:66:77:88:99"
    )
    assert arguments[arguments.index("-Gebruiker") + 1] == "nsroot"
    assert "-WatIs" not in arguments
    assert collector_calls == [], "de SSH-route mag de collector niet ook starten"
    assert "12345 MB" in text, text
    assert "df -k /var over SSH, live gelezen" in text


def test_without_a_pinned_host_key_the_collector_route_is_taken(tmp_path, loop, no_sockets):
    _result, text, collector_calls, ssh_calls = _preflight_over_ssh(tmp_path, loop, pinned=False)
    assert ssh_calls == []
    assert len(collector_calls) == 1
    assert collector_calls[0][-2:] == ["-OnlyResources", "stat/system"]
    assert "stat/system via het verzamelscript" in text


def test_without_onderhoud_the_collector_route_is_taken(tmp_path, loop, no_sockets):
    _result, text, collector_calls, ssh_calls = _preflight_over_ssh(tmp_path, loop, onderhoud=False)
    assert ssh_calls == []
    assert len(collector_calls) == 1
    assert "stat/system via het verzamelscript" in text


@pytest.mark.parametrize(
    "live,expected_reason",
    [
        (
            lambda a, t: (1, "[FOUT] kon geen SSH-sessie openen naar 10.0.0.10: hostsleutel wijkt af\n", ""),
            "hostsleutel wijkt af",
        ),
        (lambda a, t: (0, "[VRIJ_MB] veel\n", ""), "niet precies een regel [VRIJ_MB] met een geheel getal"),
        (
            lambda a, t: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd=["x"], timeout=t)),
            "tijdslimiet van 120 seconden",
        ),
    ],
)
def test_a_failed_ssh_read_is_a_read_gap_with_its_reason_and_no_second_attempt(
    tmp_path, loop, no_sockets, live, expected_reason
):
    result, text, collector_calls, ssh_calls = _preflight_over_ssh(tmp_path, loop, live=live)
    assert result.isError is False, text
    assert len(ssh_calls) == 1
    assert collector_calls == [], "geen stille cascade naar de collector"
    assert "niet beoordeeld" in text
    assert expected_reason in text
    assert "10.0.0.10" not in text
    assert "gjk/netscaler/lab/readonly" not in text


def test_a_missing_read_script_is_a_read_gap_and_starts_nothing(tmp_path, loop, no_sockets):
    _result, text, collector_calls, ssh_calls = _preflight_over_ssh(tmp_path, loop, script_present=False)
    assert ssh_calls == [] and collector_calls == []
    assert "niet beoordeeld" in text
    assert "Invoke-GjkLiveMeting.ps1" in text


def test_the_bundle_size_comes_from_the_one_bundle_in_the_firmware_directory(tmp_path, loop, no_sockets):
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "build-14.1-72.57_nc_64.tgz").write_bytes(b"\0" * (3 * 1024 * 1024))
    _result, text, _collector_calls, _ssh_calls = _preflight_over_ssh(tmp_path, loop)
    assert "bundel 3 MB + uitpakkosten 3 MB" in text, text
    assert "aangenomen bundelgrootte" not in text


def test_the_bundle_size_stays_a_named_assumption_without_a_unique_bundle(tmp_path, loop, no_sockets):
    _result, text, _collector_calls, _ssh_calls = _preflight_over_ssh(tmp_path, loop)
    assert "aangenomen bundelgrootte 1100 MB" in text, text


def test_the_backup_tool_opens_no_socket_in_the_server_process(tmp_path, loop, no_sockets):
    """De backuptool is een SCHRIJFtool: hij start een apart proces, precies
    zoals de vier bestaande. Het serverproces opent er geen socket voor.

    Same shape as the two exceptions above: a `run` stub replaces
    `subprocess.Popen` for determinism (the appliance is reached by a
    SEPARATE process regardless, so no socket of it can exist in THIS one -
    see the module docstring), and the assertions on content make this a
    measurement instead of a promise. `onderhoud_backup_maken` needs an
    action_script, a fixture_dir, an allowlist entry AND a code channel to
    exist at all - all four run under the guard here, plus
    the full propose-then-confirm cycle.

    Before this fix this stub was green for the WRONG reason
    - the read-back gate compared the device label ("lab", from `[TARGET]`)
    against the read-back detail as a substring, which passed only because
    "lab" happens to sit inside every name this target ever forms
    (`gjk_preupgrade_lab_...`). The gate now compares `result.object_name` -
    the FULL name this call commanded, read from the argument list, never
    from `[TARGET]` - against the same detail line, which is why the stub
    below still has to echo the real `-BackupNaam` value back for the call
    to succeed at all. The discriminating case (a stale object also
    containing "lab" but with a DIFFERENT full name) is measured separately
    in `test_handelen_zonder_code.py::test_a_readback_naming_an_older_backup_object_fails_the_action_even_at_exit_zero`.
    """
    forget_identities()
    script = tmp_path / "schrijf.ps1"
    script.write_text("# leeg; de stub neemt het over in de test", encoding="utf-8")

    def code_presenter(tool, target, arguments, code, proposal_text, marker, section):
        codes.append(code)

    codes: list = []

    def stub_write_script(arguments, timeout_s):
        naam = arguments[arguments.index("-BackupNaam") + 1]
        if "-WatIs" in arguments:
            return 0, "[OK] zou doen: backup maken\n[TARGET] lab\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n", ""
        return (
            0,
            (
                "[ACTIEID] id-1\n[TARGET] lab\n"
                f"[OK] teruggelezen op de collectie config/systembackup: {naam}.tgz, 41 MB, "
                "2026-09-06T14:03:12Z, level full\n"
                "[EINDSTATUS] backup gemaakt en teruggelezen\n"
            ),
            "",
        )

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        action_script=script,
        fixture_dir=tmp_path,
        action_run=stub_write_script,
        onderhoud=maintenance_config(tmp_path),
        code_presenter=code_presenter,
        allowlist=Allowlist(per_target={"lab": {"onderhoud_backup_maken": True}}),
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            voorstel = await client.call_tool("onderhoud_backup_maken", {})
            code = codes[-1]
            uitgevoerd = await client.call_tool("onderhoud_backup_maken", {"bevestiging": code})
            return voorstel, uitgevoerd

    voorstel, uitgevoerd = loop.run_until_complete(scenario())

    assert voorstel.isError is False, voorstel
    assert uitgevoerd.isError is False, " ".join(b.text for b in uitgevoerd.content if hasattr(b, "text"))
    tekst = " ".join(b.text for b in uitgevoerd.content if hasattr(b, "text"))
    assert "UITGEVOERD (onderhoud_backup_maken)" in tekst


def test_the_config_opslaan_tool_opens_no_socket_in_the_server_process(tmp_path, loop, no_sockets):
    """`config_opslaan` is a WRITING tool: its SSH script
    (Invoke-GjkConfigOpslaan.ps1) is a separate process, like the demo write
    script above, so no socket of it can exist in this one. An `action_run`
    stub replaces the process start; everything up to it - the allowlist,
    the target lookup, the open-phase gate on the ledger, the proposal, the
    redeem, the read-back judgement and the action register - runs under
    the guard."""
    forget_identities()
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# niet gebruikt door config_opslaan", encoding="utf-8")
    maintenance = maintenance_config(tmp_path)
    (Path(maintenance.runner).parent / "Invoke-GjkConfigOpslaan.ps1").write_text("# stub", encoding="ascii")
    stand = (Path(__file__).parent / "fixtures" / "configstand" / "show-ns-config-opgeslagen.txt").read_text(
        encoding="ascii"
    )
    codes: list = []

    def code_presenter(tool, target, arguments, code, proposal_text, marker, section):
        codes.append(code)

    def stub_save_script(arguments, timeout_s):
        kop = "[TARGET] nsconfig/lab (10.0.0.10) - config opslaan\n"
        if "-WatIs" in arguments:
            return 0, kop + "[OK] zou doen: save ns config op lab na een rolcontrole\n[EINDSTATUS] WAT-IS\n", ""
        actie = arguments[arguments.index("-Actieid") + 1]
        metingen = "".join(f"[METING] show ns config: {r.replace(chr(9), ' ')}\n" for r in stand.split("\n"))
        return (
            0,
            kop + f"[ACTIEID] {actie}\n{metingen}[METINGSTATUS] show ns config: exitcode=0\n[EINDSTATUS] OPGESLAGEN\n",
            "",
        )

    server = build_server(
        _real_export(tmp_path),
        _real_knowledge(tmp_path),
        targets_path=_preflight_targets(tmp_path, pinned=True),
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=stub_save_script,
        onderhoud=maintenance,
        code_presenter=code_presenter,
        allowlist=Allowlist(per_target={"lab": {"config_opslaan": True}}),
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            voorstel = await client.call_tool("config_opslaan", {})
            uitgevoerd = await client.call_tool("config_opslaan", {"bevestiging": codes[-1]})
            return voorstel, uitgevoerd

    voorstel, uitgevoerd = loop.run_until_complete(scenario())

    assert voorstel.isError is False, voorstel
    tekst = " ".join(b.text for b in uitgevoerd.content if hasattr(b, "text"))
    assert uitgevoerd.isError is False, tekst
    assert "UITGEVOERD (config_opslaan)" in tekst
    assert "laatste opslag Thu Sep 24 10:14:40 2026 is niet ouder dan laatste wijziging" in tekst


def test_the_upgrade_fase_tool_opens_no_socket_in_the_server_process(tmp_path, loop, no_sockets):
    """`onderhoud_upgrade_fase` is een SCHRIJFtool en valt dus buiten de
    no-socket-guard net als `onderhoud_backup_maken` hierboven - de
    faserunner is een APART PROCES (`handelen.start_detached()`, en de
    `-WatIs`-preview via een gewoon `subprocess.Popen`), dus geen socket
    ervan kan in DIT proces bestaan. Anders dan de backuptool hierboven kan
    dit pad niet met een `action_run`-stub gemeten worden - de
    faserunner's argumentvorm heeft niets met het schrijfscript gemeen
    (scripts/README.md) - dus dit draait een ECHTE Python-nep-runner als
    apart proces, precies zoals tests/test_upgrade_fase.py doet."""
    forget_identities()
    export_dir = _real_export(tmp_path)
    # De export beschrijft het doel van deze fase, zoals status_ververs hem
    # achterlaat: een export van een ander doel, of zonder doel, weigert de
    # fase al voor de preview.
    _anchor_target(export_dir, "lab")
    knowledge_path = _real_knowledge(tmp_path)
    script = tmp_path / "schrijf.ps1"
    script.write_text("# ongebruikt door onderhoud_upgrade_fase", encoding="utf-8")
    doelen = tmp_path / "doelen.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "GJK/Test/lab/nitro-write",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    firmwaremap = tmp_path / "firmware"
    firmwaremap.mkdir()
    (firmwaremap / "build-14.1-72.57_nc_64.tgz").write_bytes(b"x")
    (firmwaremap / "build-14.1-72.57_nc_64.tgz.sha256").write_text("deadbeef", encoding="utf-8")
    runner = tmp_path / "nep_runner.py"
    runner.write_text(
        "import json, sys\n"
        "from datetime import datetime, timezone\n"
        "argv = sys.argv[1:]\n"
        "d = dict(zip(argv, argv[1:]))\n"
        "print('[TARGET] ' + d.get('-Doel', '') + ' (' + d.get('-Adres', '') + ') - fase '\n"
        "      + d.get('-Fase', '') + ' naar build ' + d.get('-Doelbuild', ''))\n"
        "print('[ACTIEID] upgrade-' + d.get('-Fase', '') + '-'\n"
        "      + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))\n"
        "if '-WatIs' in argv:\n"
        "    sys.exit(0)\n"
        "regel = {'tijd': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),\n"
        "         'run': d.get('-Run', ''), 'doel': d.get('-Doel', ''), 'fase': d.get('-Fase', ''),\n"
        "         'gebeurtenis': 'fase_gestart', 'poort': [], 'uitkomst': 'gestart',\n"
        "         'bewijs': 'nep-runner', 'actieid': d.get('-Actieid'),\n"
        "         'bevestiger': d.get('-Bevestiger'),\n"
        "         'gestart': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),\n"
        "         'geeindigd': None}\n"
        "with open(d.get('-Ledger', ''), 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(regel) + chr(10))\n",
        encoding="utf-8",
    )
    onderhoud = MaintenanceConfig(
        runner=runner,
        ledgermap=ledgermap,
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )

    class IdentifyingPresenter:
        label = "sso"

        def __init__(self):
            self.calls = []
            self._per_code = {}

        def __call__(self, tool, target, arguments, code, proposal_text, marker, section):
            self.calls.append(code)
            self._per_code[code] = "beheerder@voorbeeld.invalid"

        def bevestiger_for(self, code):
            return self._per_code.pop(code, None)

    presenter = IdentifyingPresenter()
    server = build_server(
        export_dir,
        knowledge_path,
        targets_path=doelen,
        action_script=script,
        fixture_dir=tmp_path,
        code_presenter=presenter,
        onderhoud=onderhoud,
        allowlist=Allowlist(per_target={"lab": {"onderhoud_upgrade_fase": True}}),
        provenance_dir=provenance_dir_for(export_dir),
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            voorstel = await client.call_tool(
                "onderhoud_upgrade_fase",
                {"fase": "R0", "snapshotverwijzing": "checkpoint-1"},
            )
            code = presenter.calls[-1]
            uitgevoerd = await client.call_tool(
                "onderhoud_upgrade_fase",
                {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code},
            )
            return voorstel, uitgevoerd

    voorstel, uitgevoerd = loop.run_until_complete(scenario())

    assert voorstel.isError is False, voorstel
    tekst = " ".join(b.text for b in uitgevoerd.content if hasattr(b, "text"))
    assert uitgevoerd.isError is False, tekst
    assert "FASE GESTART (onderhoud_upgrade_fase)" in tekst
    assert presenter.calls, "de tool moet echt een bevestigingscode hebben uitgegeven"


def test_the_upgrade_stand_tool_opens_no_socket_in_the_server_process(tmp_path, loop, no_sockets):
    """`onderhoud_upgrade_stand` is a READING tool - unlike
    `onderhoud_backup_maken`/`onderhoud_upgrade_fase` above it starts no
    separate process at all and belongs in THIS file's guarantee, not among
    the two documented exceptions (`NO_SOCKET_EXCEPTIONS`): it only ever
    reads a ledger file off local disk, exactly like every other reading
    tool this file proves. The content assertions at the end are what make
    this a measurement instead of a promise - see the module docstring.
    """
    forget_identities()
    export_dir = _real_export(tmp_path)
    knowledge_path = _real_knowledge(tmp_path)
    doelen = tmp_path / "doelen.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "GJK/Test/lab/nitro-write",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    run_name = "20260906T100000Z-lab"
    ledger_pad = ledgermap / f"{run_name}.jsonl"
    append_line(
        ledger_pad,
        {
            "tijd": "2026-09-06T10:00:00Z",
            "run": run_name,
            "doel": "lab",
            "fase": "R0",
            "gebeurtenis": "fase_gestart",
            "poort": [],
            "uitkomst": "gestart",
            "bewijs": "",
            "actieid": "a-r0",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T10:00:00Z",
            "geeindigd": None,
        },
    )
    append_line(
        ledger_pad,
        {
            "tijd": "2026-09-06T10:05:00Z",
            "run": run_name,
            "doel": "lab",
            "fase": "R0",
            "gebeurtenis": "voormeting_vast",
            "poort": [
                {
                    "naam": "backupobject aanwezig",
                    "type": "bewijs",
                    "uitkomst": "open",
                    "bewijs": "config/systembackup-collectie draagt gjk_preupgrade_lab_20260906",
                    "reden": "",
                }
            ],
            "uitkomst": "geslaagd",
            "bewijs": "alle poorten van deze fase staan open",
            "actieid": "a-r0",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T10:00:00Z",
            "geeindigd": "2026-09-06T10:05:00Z",
        },
    )
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=ledgermap,
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    server = build_server(
        export_dir,
        knowledge_path,
        targets_path=doelen,
        onderhoud=onderhoud,
        provenance_dir=provenance_dir_for(export_dir),
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("onderhoud_upgrade_stand", {})

    result = loop.run_until_complete(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "R0: geslaagd" in text
    assert "backupobject aanwezig" in text
    assert "laatste ledgerregel" in text
    # The one target is picked without a `doel` argument (the "one
    # configured target needs no doel" convenience) and the one run without
    # a `run` argument (the "latest run" default) - both exercised here by
    # calling with no arguments at all.
    assert "R1: niet beoordeeld" in text


def test_the_rapport_na_upgrade_tool_opens_no_socket_in_the_server_process(tmp_path, loop, no_sockets):
    """`rapport_na_upgrade` is a READING tool, the same
    kind of guarantee as `onderhoud_upgrade_stand` right above it: it reads
    only the loaded export/knowledge and a ledger file off local disk, and
    belongs in THIS file's guarantee rather than among the two documented
    exceptions (`NO_SOCKET_EXCEPTIONS`). Block 1 of its design (the
    before/after comparison) is not wired in on this branch - see
    `nsmcp.after_upgrade`'s module docstring - so this only exercises
    blocks 2 (CVE), 3 (extra step) and 4 (anchor/family counts)."""
    forget_identities()
    export_dir = _real_export(tmp_path)
    # The export describes the target whose ledger the report reads.
    _anchor_target(export_dir, "lab")
    knowledge_path = _real_knowledge(tmp_path)
    doelen = tmp_path / "doelen.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "GJK/Test/lab/nitro-write",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    run_name = "20260906T100000Z-lab"
    ledger_pad = ledgermap / f"{run_name}.jsonl"
    anker = hashlib.sha256(b"no-network-anchor").hexdigest()
    anker_poort = {
        "naam": "configuratie-anker",
        "type": "bewijs",
        "uitkomst": "open",
        "bewijs": f"anker={anker}; -encrypted=1, set ns encryptionParams=2, set ns rpcNode=1",
        "reden": "",
    }
    familie_poort = {
        "naam": "familietellingen",
        "type": "bewijs",
        "uitkomst": "open",
        "bewijs": (
            "familietellingen: lbvserver=2, csvserver=1, vpnvserver=0, "
            "authenticationvserver=0, service=2, servicegroup=1, sslcertkey=1, lbmonitor=1"
        ),
        "reden": "",
    }
    append_line(
        ledger_pad,
        {
            "tijd": "2026-09-06T10:00:00Z",
            "run": run_name,
            "doel": "lab",
            "fase": "R0",
            "gebeurtenis": "voormeting_vast",
            "poort": [anker_poort, familie_poort],
            "uitkomst": "geslaagd",
            "bewijs": "alle poorten van deze fase staan open",
            "actieid": "a-r0",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T10:00:00Z",
            "geeindigd": "2026-09-06T10:05:00Z",
        },
    )
    append_line(
        ledger_pad,
        {
            "tijd": "2026-09-06T14:00:00Z",
            "run": run_name,
            "doel": "lab",
            "fase": "R5",
            "gebeurtenis": "fase_geslaagd",
            "poort": [anker_poort, familie_poort],
            "uitkomst": "geslaagd",
            "bewijs": "alle poorten van deze fase staan open",
            "actieid": "a-r5",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T13:55:00Z",
            "geeindigd": "2026-09-06T14:00:00Z",
        },
    )
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=ledgermap,
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    server = build_server(
        export_dir,
        knowledge_path,
        targets_path=doelen,
        onderhoud=onderhoud,
        provenance_dir=provenance_dir_for(export_dir),
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("rapport_na_upgrade", {})

    result = loop.run_until_complete(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "configuratie-anker" in text
    assert "gelijk" in text
    assert "familietelling" in text
    assert "extra stap na de upgrade" in text
    assert "NIET BEOORDEELD IN DEZE VERSIE" in text


def test_rapport_vergelijk_refuses_a_path_and_opens_no_socket(tmp_path, loop, no_sockets):
    forget_identities()
    server = build_server(_real_export(tmp_path), _real_knowledge(tmp_path))

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("rapport_vergelijk", {"mapA": "../geheim", "mapB": "export"})

    result = loop.run_until_complete(scenario())
    assert result.isError is True
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "geen pad" in text
    assert "geheim" not in text, "de weigering herhaalt de naam niet"


def test_rapport_vergelijk_refuses_every_path_escape_form(tmp_path, loop, no_sockets):
    """`mapA`/`mapB` take only a plain sibling directory NAME - every
    one of these forms must be refused, without echoing the value. Most
    are closed structurally by `is_safe_run_name`'s character class
    (a path separator, a drive/UNC/ADS colon, "."/".." as the whole name,
    a reserved device name, a trailing dot); this test MEASURES that
    instead of assuming it, one form at a time. A junction escape is its
    own test below - `is_safe_run_name` cannot see it at all, since a
    junction's own NAME is a perfectly ordinary one."""
    forget_identities()
    export_dir = _real_export(tmp_path)
    server = build_server(export_dir, _real_knowledge(tmp_path))

    forms = (
        "../geheim",
        "..\\geheim",
        "export/../export",
        "C:\\Windows",
        "C:",
        "/etc",
        "\\\\srv\\share",
        "export:stream",
        ".",
        "..",
        "CON",
        "export.",
    )

    async def scenario():
        results = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for form in forms:
                results[form] = await client.call_tool("rapport_vergelijk", {"mapA": form, "mapB": "export"})
        return results

    results = loop.run_until_complete(scenario())
    for form, result in results.items():
        assert result.isError is True, f"{form!r} had geweigerd moeten worden"
        text = " ".join(b.text for b in result.content if hasattr(b, "text"))
        assert "geheim" not in text, f"{form!r}: de weigering herhaalt de naam niet"


def test_rapport_vergelijk_refuses_a_junction_that_points_outside_the_export_root(tmp_path, loop, no_sockets):
    """A Windows junction (`mklink /J`) can be named exactly like a
    plain sibling directory while pointing anywhere on disk -
    `is_safe_run_name` has no way to see that, so `_inside_export_root()`
    must additionally refuse a reparse point (`export.plain_path()`, the
    same containment discipline `retention._owned_manifest` already
    applies to a kept sibling) and confirm the RESOLVED path still sits
    under the same parent. Skips (rather than fails) when this system
    cannot create a junction at all - that is an environment limit, not a
    product defect."""
    forget_identities()
    export_dir = _real_export(tmp_path)
    outside = tmp_path / "buiten" / "geheim"
    (outside / "objects").mkdir(parents=True)
    junction = export_dir.parent / "junctie"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
    )
    if created.returncode != 0 or not junction.is_dir():
        pytest.skip(f"kon geen junction aanmaken op dit systeem: {(created.stderr or created.stdout).strip()}")

    server = build_server(export_dir, _real_knowledge(tmp_path))

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("rapport_vergelijk", {"mapA": "junctie", "mapB": "export"})

    result = loop.run_until_complete(scenario())
    assert result.isError is True, "een junction naar buiten de exportroot moet geweigerd worden"
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "buiten" not in text and "geheim" not in text


def test_rapport_vergelijk_refuses_an_unknown_mode_without_echoing_it(tmp_path, loop, no_sockets):
    """Preflight ruling: an unknown `modus` is refused WITHOUT echoing the
    supplied value - only the four valid modes are named. `compare.py`'s own
    `ValueError` (tests/test_compare.py) does echo it for a programmatic
    caller; this tool's client-facing refusal does not, the same discipline
    `_inside_export_root()` applies to `mapA`/`mapB`."""
    forget_identities()
    server = build_server(_real_export(tmp_path), _real_knowledge(tmp_path))

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool(
                "rapport_vergelijk", {"mapA": "export", "mapB": "export", "modus": "zomaar-iets"}
            )

    result = loop.run_until_complete(scenario())
    assert result.isError is True
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert "zomaar-iets" not in text, "de weigering herhaalt de aangeleverde modus niet"
    for mode in ("HA-parity", "drift", "run-diff", "pre/post"):
        assert mode in text


def test_rapport_wat_is_er_veranderd_lands_on_the_same_engine_as_rapport_vergelijk(
    tmp_path, loop, no_sockets, monkeypatch
):
    """Ruling: `rapport_wat_is_er_veranderd` must call LITERALLY the same
    public engine as `rapport_vergelijk` - a spy on `compare_answer`
    (patched where mcp_server.py imported it, the same seam every scan
    stub in this file already patches) plus a behaviour comparison of both
    tools' rendered answers, normalized for the one line that legitimately
    differs by design: the data stamp. `rapport_vergelijk(mapA, mapB, ...)`
    stamps from mapA (the LEFT/older side); this tool stamps from the
    CURRENT export - both correct for their own tool, and neither a second
    comparison implementation.
    """
    import nsmcp.mcp_server as mcp_server_module

    forget_identities()
    current = _real_export(tmp_path)
    kept = tmp_path / f"{current.name}{KEPT_SUFFIX}20260819T090000Z"
    shutil.copytree(current, kept)
    manifest_path = kept / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collectedAtUtc"] = "2026-08-19T09:00:00.0000000Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    calls = []
    original_compare_answer = mcp_server_module.compare_answer

    def spy(left, right, knowledge, mode):
        calls.append(mode)
        return original_compare_answer(left, right, knowledge, mode)

    monkeypatch.setattr(mcp_server_module, "compare_answer", spy)
    server = _complete_server(tmp_path, current, _real_knowledge(tmp_path))

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            a = await client.call_tool(
                "rapport_vergelijk", {"mapA": kept.name, "mapB": current.name, "modus": "run-diff"}
            )
            b = await client.call_tool("rapport_wat_is_er_veranderd", {})
            return a, b

    result_a, result_b = loop.run_until_complete(scenario())
    assert result_a.isError is False and result_b.isError is False
    text_a = " ".join(b.text for b in result_a.content if hasattr(b, "text"))
    text_b = " ".join(b.text for b in result_b.content if hasattr(b, "text"))

    assert calls == ["run-diff", "run-diff"], "beide tools moeten dezelfde motor aanroepen"

    def without_data_stamp(text: str) -> str:
        lines = text.rstrip("\n").split("\n")
        assert lines[-1].startswith("Gegevens"), "onverwachte antwoordvorm: geen Gegevens-regel"
        return "\n".join(lines[:-1])

    assert without_data_stamp(text_a) == without_data_stamp(text_b), (
        "rapport_wat_is_er_veranderd moet hetzelfde gedrag tonen als "
        "rapport_vergelijk in de modus run-diff, op de kennis- en "
        "inhoudsregels na de datastempel"
    )
