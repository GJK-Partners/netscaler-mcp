"""The five-minute path, tested rather than described.

Measured before this existed: a newcomer took five detours to the first
answer, because the repository ships a complete real export that the README
never mentioned."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_example_configuration_points_at_files_that_exist():
    config = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    assert (ROOT / config["exportmap"]).is_dir()
    assert (ROOT / config["kennispad"]).is_file()


def test_the_example_configuration_really_builds_a_server(tmp_path):
    from nsmcp.start import build_server_from_config

    raw = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    raw["exportmap"] = str(ROOT / raw["exportmap"])
    raw["kennispad"] = str(ROOT / raw["kennispad"])
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    server = build_server_from_config(path)
    assert server is not None


def test_the_example_configuration_pins_the_example_knowledge_package(capsys):
    """The pin in config.example.json is what the digest command prints for
    the example package: a change to kennis.example.json without a new pin
    fails here, not only in the answers of whoever copies the example."""
    from nsmcp.knowledge import main

    config = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    assert main(["--digest", str(ROOT / config["kennispad"])]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert config.get("kennispin") == printed["kennispin"]


def test_the_example_configuration_answers_on_a_pinned_package(tmp_path):
    import asyncio

    import mcp.types as types
    from mcp.shared.memory import create_connected_server_and_client_session

    from nsmcp.start import build_server_from_config

    raw = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    raw["exportmap"] = str(ROOT / raw["exportmap"])
    raw["kennispad"] = str(ROOT / raw["kennispad"])
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    async def scenario():
        async with create_connected_server_and_client_session(
            build_server_from_config(path), client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_update_advies", {})

    result = asyncio.run(scenario())
    text = "".join(block.text for block in result.content if hasattr(block, "text"))
    assert result.isError is False, text
    assert "kennispin" not in text, text
    assert "niet gepind" not in text, text


def test_the_minimal_client_produces_a_real_answer_from_another_directory(tmp_path):
    """config.example.json uses
    RELATIVE paths and start.py resolves them against the process CWD, not
    against the config file's own directory. The test above proves the
    config's CONTENTS, never the documented demo command - it rewrites both
    paths to absolute BEFORE building a server, so a caller running `python
    examples/minimal_client.py` from any directory other than the
    repository root was never exercised: `examples/minimal_client.py` makes
    CONFIG absolute but set no `cwd` on StdioServerParameters, so the CHILD
    process inherited the CALLER's cwd. The child's honest "Fout: exportmap
    niet gevonden: ..." went to stderr, `stdio_client` swallowed it, and the
    caller got an unreadable ExceptionGroup ending in McpError: Connection
    closed - this is the only test that runs the documented command as a
    real subprocess from a non-root directory, so it is the only one that
    would have caught that."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "minimal_client.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert "tools:" in result.stdout
    # A real answer computed from the shipped fixture export, not a stub.
    assert "14.1-72.57" in result.stdout
    assert "ExceptionGroup" not in result.stderr
    assert "Traceback" not in result.stderr


def test_the_minimal_client_config_not_found_gives_a_clean_error(tmp_path):
    """The demo's error branch (main()'s try/except around
    asyncio.run(), added alongside the cwd= fix above) had no test at
    all: the committed subprocess test above only exercises the happy
    path. This copies minimal_client.py two directories deep into
    tmp_path, so its own CONFIG = Path(__file__).resolve().parent.parent
    / "config.example.json" resolves to a path that does not exist -
    the same failure mode as a broken install, not merely a wrong cwd.
    The child (nsmcp.start) fails immediately with its own "Fout:
    configuratiebestand niet gevonden: ..." and exit code 1, before any
    MCP handshake completes; this proves the wrapping try/except in
    minimal_client.py turns that into a clean, readable failure instead
    of the raw ExceptionGroup/McpError traceback the happy-path test
    above guards against."""
    import shutil
    import subprocess
    import sys

    script_dir = tmp_path / "sub"
    script_dir.mkdir()
    copy = script_dir / "minimal_client.py"
    shutil.copy(ROOT / "examples" / "minimal_client.py", copy)

    result = subprocess.run(
        [sys.executable, str(copy)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert "Fout: kon geen antwoord ophalen bij de server" in result.stderr
    assert "ExceptionGroup" not in result.stdout
    assert "ExceptionGroup" not in result.stderr
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_the_example_knowledge_package_says_it_is_an_example():
    from datetime import date

    from nsmcp.knowledge import load_knowledge

    knowledge = load_knowledge(ROOT / "kennis.example.json", today=date(2026, 9, 5))
    assert knowledge.missing is False
    assert "VOORBEELD" in (knowledge.version or "")


def test_the_fixture_carries_a_readme_that_says_where_it_came_from():
    text = (ROOT / "tests/fixtures/lab-export-vpx-20260826/README.md").read_text(encoding="utf-8")
    for word in ("2026-08-26", "NSHC", "redacted", "lab"):
        assert word in text


def test_the_readme_points_at_the_runnable_export_and_the_client_example():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "tests/fixtures/lab-export-vpx-20260826" in text
    assert "examples/minimal_client.py" in text
    assert "config.example.json" in text


def test_the_demo_path_prints_no_stderr_noise_before_the_first_answer():
    """Measured on the newcomer path, three stderr lines
    printed BEFORE the first answer - the pydantic_settings
    IncompleteFieldDefinitionWarning `mcp==1.29.0` carried (with its own
    traceback line), and two FastMCP INFO lines ("Processing request of
    type ..."). Design par. 2.6 item 7: these get cleaned up or explained
    in the demo path; cleaned up is the choice made here, so the documented
    `python examples/minimal_client.py` command prints nothing on stderr by
    default. `mcp==1.30.0` no longer emits the warning; the request-log
    lines remain.

    The second run sets NSMCP_DEBUG=1 and asserts the request-log marker
    IS there - proving this test would have caught its absence rather than
    passing by accident on a path that was already quiet."""
    import os
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "minimal_client.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert result.stderr == "", result.stderr

    debug_env = dict(os.environ)
    debug_env["NSMCP_DEBUG"] = "1"
    debug_result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "minimal_client.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=debug_env,
    )
    assert debug_result.returncode == 0, debug_result.stderr
    assert "Processing request of type" in debug_result.stderr
