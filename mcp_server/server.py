"""
research-agent MCP server.

Exposes a single tool:

    research(prompt: str) -> { status, report_path, error? }

The host Claude session calls this. The server spawns the container-side
research agent, waits for it to finish, runs the scanner, and either moves
the report into the reports/ dir or returns an error.

Seed implementation: subprocess-per-call. Planned upgrade: long-running
container worker with unix-socket IPC.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Paths are relative to repo root so the server can run outside the container
# during development.
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_DIR = REPO_ROOT / "scratch"
REPORTS_DIR = REPO_ROOT / "reports"
AGENT_DIR = REPO_ROOT / "agent"

# Override with env var when running inside the container. The container mounts
# host reports/ at /out.
SCRATCH_DIR = Path(os.environ.get("RESEARCH_SCRATCH_DIR", SCRATCH_DIR))
REPORTS_DIR = Path(os.environ.get("RESEARCH_REPORTS_DIR", REPORTS_DIR))

# Path to the Claude Code binary used for the agent. Default: claude on PATH.
CLAUDE_BIN = os.environ.get("RESEARCH_CLAUDE_BIN", "claude")

# Timeout for a single research call (seconds).
AGENT_TIMEOUT = int(os.environ.get("RESEARCH_AGENT_TIMEOUT", "600"))


def _ensure_dirs() -> None:
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _run_agent(prompt: str, scratch_path: Path) -> tuple[int, str]:
    """Invoke the container-side Claude agent. Returns (exit_code, combined_output)."""
    full_prompt = (
        f"You are the research-agent. Investigate the following prompt "
        f"using the available web MCPs (exa, tavily), then write a cited "
        f"markdown report to exactly this path:\n\n"
        f"    {scratch_path}\n\n"
        f"Do not write to any other location. Do not print the report to "
        f"stdout. When done, say only 'DONE' and nothing else.\n\n"
        f"Research prompt:\n\n{prompt}"
    )
    # NOTE: When containerized, this subprocess.run is replaced by IPC to the
    # long-running container worker. For the seed, spawn-per-call is fine.
    result = subprocess.run(
        [CLAUDE_BIN, "-p", full_prompt, "--cwd", str(AGENT_DIR)],
        capture_output=True,
        text=True,
        timeout=AGENT_TIMEOUT,
    )
    return result.returncode, (result.stdout + result.stderr)


def _scan(path: Path) -> tuple[bool, str]:
    """Run the scanner on the scratch report. Returns (ok, reason)."""
    # Lazy import so the server starts even if scanner deps are missing.
    from scanner.regex import scan_file

    return scan_file(path)


mcp = FastMCP("research-agent")


@mcp.tool()
def research(prompt: str) -> dict:
    """Run a web-research task in the isolated agent and return the report path.

    Args:
        prompt: The research question or instructions for the agent.

    Returns:
        A dict with status='done' and report_path on success, or status='error'
        and an error reason on failure.
    """
    _ensure_dirs()
    report_id = uuid.uuid4().hex
    scratch_path = SCRATCH_DIR / f"{report_id}.md"
    try:
        code, output = _run_agent(prompt, scratch_path)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"agent timeout after {AGENT_TIMEOUT}s"}

    if not scratch_path.exists():
        return {
            "status": "error",
            "error": f"agent did not produce report (exit={code})",
        }

    ok, reason = _scan(scratch_path)
    if not ok:
        scratch_path.unlink(missing_ok=True)
        return {"status": "error", "error": f"scanner rejected report: {reason}"}

    final_path = REPORTS_DIR / f"{report_id}.md"
    shutil.move(str(scratch_path), str(final_path))
    return {"status": "done", "report_path": str(final_path)}


if __name__ == "__main__":
    mcp.run()
