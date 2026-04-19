"""Run the same research prompt at fast / normal / deep and report timings.

Usage:
    uv run python3 tests/bench_depths.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


REPO_ROOT = Path(__file__).resolve().parent.parent
PROMPT = (
    "Summarise the main security concerns with Model Context Protocol "
    "(MCP) servers as of 2026. One paragraph, 3-5 citations."
)


async def run_one(depth: str) -> dict:
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
            result = await session.call_tool(
                "research", {"prompt": PROMPT, "depth": depth}
            )
            out: dict = {}
            for item in result.content:
                if hasattr(item, "text"):
                    try:
                        out = json.loads(item.text)
                    except Exception:
                        out = {"raw": item.text[:200]}
            return {"depth": depth, "isError": result.isError, **out}


async def main() -> int:
    rows = []
    for depth in ("fast", "normal", "deep"):
        print(f"== {depth} ==", flush=True)
        r = await run_one(depth)
        rows.append(r)
        t = r.get("timings_ms", {})
        print(
            f"  status={r.get('status')} "
            f"agent={t.get('agent')}ms scan={t.get('scan')}ms "
            f"total={t.get('total')}ms "
            f"path={r.get('report_path', '').split('/')[-1]}"
        )
        if r.get("status") == "error":
            print(f"  error={r.get('error','')[:200]}")
    print("\n== summary ==")
    print(f"{'depth':<8}{'agent(s)':>12}{'scan(ms)':>12}{'total(s)':>12}")
    for r in rows:
        t = r.get("timings_ms", {})
        a = t.get("agent", 0) / 1000
        s = t.get("scan", 0)
        tot = t.get("total", 0) / 1000
        print(f"{r['depth']:<8}{a:>12.1f}{s:>12}{tot:>12.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
