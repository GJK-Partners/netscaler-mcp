"""The shortest possible MCP client for this server: list the tools, ask one
question, print the answer.

Run it from the repository root, with the package installed
(`pip install -e .`):

    python examples/minimal_client.py

It starts the server over stdio with `config.example.json`, which points at the
real lab export shipped in `tests/fixtures/`. The answer that comes back is
computed from that export - no appliance, no network, no API key.
"""
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CONFIG = Path(__file__).resolve().parent.parent / "config.example.json"


async def main() -> None:
    # NSMCP_DEBUG, forwarded on top of the SDK's own safe default
    # environment (StdioServerParameters.env=None would otherwise pass only
    # a fixed allowlist - PATH and the like - never the caller's own
    # variables). This is the one variable that restores the server's
    # normal startup noise (a third-party warning and the FastMCP log lines
    # per request) for diagnosis; every other rejection already
    # reaches this script's own stderr unfiltered.
    debug_env = (
        {"NSMCP_DEBUG": os.environ["NSMCP_DEBUG"]} if os.environ.get("NSMCP_DEBUG") else None
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "nsmcp.start", str(CONFIG)],
        # config.example.json uses paths RELATIVE TO ITS OWN DIRECTORY;
        # since 1.0.2 start.py resolves them against that directory, so the
        # working directory no longer matters. Kept so the child process
        # runs in the repository whatever directory this script is run from.
        cwd=CONFIG.parent,
        env=debug_env,
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools:", ", ".join(tool.name for tool in tools.tools))
            result = await session.call_tool("status_overzicht", {})
            for block in result.content:
                print(getattr(block, "text", block))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # noqa: BLE001 - top-level demo entry point
        # Without this, any failure here (the server process could not
        # start, could not be reached, or closed the connection) surfaced
        # as an unreadable 30-line ExceptionGroup/McpError traceback -
        # exactly wrong for the five-minute path this script exists for.
        print(f"Fout: kon geen antwoord ophalen bij de server: {exc}", file=sys.stderr)
        sys.exit(1)
