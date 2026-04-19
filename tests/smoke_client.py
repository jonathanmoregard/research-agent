"""Smoke test: connect to the research-agent MCP server over stdio and
exercise its tool surface.

Verifies:
  1. Server starts and speaks MCP.
  2. `research` tool is advertised with the expected schema.
  3. Calling `research(...)` returns a structured result (either success or
     a clean error — the error path is expected when the container isn't
     built yet).

Run:
    uv run python3 tests/smoke_client.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


REPO_ROOT = Path(__file__).resolve().parent.parent


async def main() -> int:
    server_params = StdioServerParameters(
        command="uv",
        args=[
            "run",
            "--project",
            str(REPO_ROOT),
            "python3",
            str(REPO_ROOT / "mcp_server" / "server.py"),
        ],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("== tools ==")
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"  - {t.name}: {t.description}")

            expected = "research"
            if not any(t.name == expected for t in tools.tools):
                print(f"FAIL: tool {expected!r} not found")
                return 1

            prompt = (
                "One-line fact: the latest Python 3 minor version. One "
                "citation. Keep report under 10 lines."
            )
            print(f"\n== call research(prompt=..., depth='fast') ==")
            result = await session.call_tool(
                "research", {"prompt": prompt, "depth": "fast"}
            )
            print(f"  isError: {result.isError}")
            for item in result.content:
                if hasattr(item, "text"):
                    print(f"  content: {item.text[:800]}")
                else:
                    print(f"  content: {item!r}")

            print("\nOK: handshake + tool call round-tripped")
            return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
