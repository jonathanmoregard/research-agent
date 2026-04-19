"""Fire N deep-research calls in parallel against the local MCP server.

Usage:
    uv run python3 tests/dispatch_research.py prompts.json out_dir

Writes: <out_dir>/index.json with entries {topic, path, timings_ms, status}.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


REPO_ROOT = Path(__file__).resolve().parent.parent


async def run_one(topic: str, prompt: str) -> dict:
    params = StdioServerParameters(
        command="uv",
        args=[
            "run", "--project", str(REPO_ROOT),
            "python3", str(REPO_ROOT / "mcp_server" / "server.py"),
        ],
    )
    start = time.monotonic()
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "research", {"prompt": prompt, "depth": "deep"}
                )
                out: dict = {"topic": topic, "wall_s": time.monotonic() - start}
                for item in result.content:
                    if hasattr(item, "text"):
                        try:
                            out.update(json.loads(item.text))
                        except Exception:
                            out["raw"] = item.text[:300]
                out["isError"] = result.isError
                return out
    except Exception as e:
        return {"topic": topic, "status": "error", "error": f"dispatch: {e}", "wall_s": time.monotonic() - start}


async def main(prompts_path: str, out_dir: str) -> int:
    with open(prompts_path) as f:
        topics = json.load(f)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"Dispatching {len(topics)} deep-research calls in parallel...", flush=True)
    results = await asyncio.gather(
        *(run_one(t["topic"], t["prompt"]) for t in topics)
    )

    index = []
    for t, r in zip(topics, results):
        entry = {
            "topic": t["topic"],
            "status": r.get("status"),
            "wall_s": round(r.get("wall_s", 0), 1),
            "timings_ms": r.get("timings_ms"),
            "report_path": r.get("report_path"),
            "error": r.get("error"),
        }
        index.append(entry)
        print(f"  [{r.get('status','?')}] {t['topic']} ({entry['wall_s']}s)")
    (out_path / "index.json").write_text(json.dumps(index, indent=2))
    print(f"\nIndex: {out_path / 'index.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
