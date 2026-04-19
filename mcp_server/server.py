"""
research-agent MCP server (host-side).

Exposes one tool:

    research(prompt: str) -> { status, report_path, error? }

Flow per call:
  1. Host MCP server receives prompt.
  2. Writes prompt to a temp file on the host.
  3. `docker exec` into the long-running research container, which runs
     scripts/run-agent.sh. That script spawns a fresh bubblewrap jail —
     new tmpfs $HOME, new tmpfs /tmp, read-only system, writable-only
     to one pre-created report file under /out/<uuid>.md.
  4. When bwrap exits, tmpfs is reaped — no state leaks to the next call.
  5. The report lands in the host `reports/` dir (bind-mounted at /out).
  6. Scanner runs on the host, moves file out of scratch-equivalent
     staging (here: the file is already in reports/, so scanner either
     approves or we delete + return error).

The container stays hot so there is no per-call startup cost. Per-call
state isolation is enforced by bubblewrap, not by container restart.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = Path(os.environ.get("RESEARCH_REPORTS_DIR", REPO_ROOT / "reports"))

# Name of the long-running container that holds the agent. Matches the
# `name` field in .devcontainer/devcontainer.json (actual runtime name will
# vary with the orchestrator — override via env).
CONTAINER = os.environ.get("RESEARCH_CONTAINER", "research-agent")

# Timeout for a single research call (seconds).
AGENT_TIMEOUT = int(os.environ.get("RESEARCH_AGENT_TIMEOUT", "600"))

# Where the container sees the agent scripts. Matches the workspace mount
# created by devcontainer.json (default: /workspace).
CONTAINER_WORKSPACE = os.environ.get("RESEARCH_CONTAINER_WORKSPACE", "/workspace")

PROMPT_TEMPLATE = (
    "You are the research-agent. Investigate the following prompt using the "
    "available web MCPs (exa, tavily), then write a cited markdown report to "
    "exactly this path:\n\n"
    "    {scratch_path}\n\n"
    "Do not write to any other location. Do not print the report to stdout. "
    "When done, say only 'DONE' and nothing else.\n\n"
    "Research prompt:\n\n{prompt}\n"
)


def _run_agent(prompt: str, report_id: str) -> tuple[int, str]:
    """Run a single research call inside the container's bubblewrap jail.

    Returns (exit_code, combined_output).
    """
    # Scratch path *as seen from inside the bwrap jail* — /scratch/<uuid>.md.
    # The host-visible equivalent is the pre-created reports/<uuid>.md file
    # that run-agent.sh bind-mounts into /scratch for the jail.
    scratch_path = f"/scratch/{report_id}.md"
    full_prompt = PROMPT_TEMPLATE.format(scratch_path=scratch_path, prompt=prompt)

    # Ship the prompt into the container via a temp file to avoid shell
    # quoting issues with arbitrary characters.
    with tempfile.NamedTemporaryFile(
        "w", prefix="research-prompt-", suffix=".txt", delete=False
    ) as tmp:
        tmp.write(full_prompt)
        host_prompt_file = tmp.name
    container_prompt_file = f"/tmp/research-prompt-{report_id}.txt"

    try:
        subprocess.run(
            [
                "docker",
                "cp",
                host_prompt_file,
                f"{CONTAINER}:{container_prompt_file}",
            ],
            check=True,
            capture_output=True,
        )
        result = subprocess.run(
            [
                "docker",
                "exec",
                CONTAINER,
                "bash",
                f"{CONTAINER_WORKSPACE}/scripts/run-agent.sh",
                report_id,
                container_prompt_file,
            ],
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT,
        )
        return result.returncode, (result.stdout + result.stderr)
    finally:
        Path(host_prompt_file).unlink(missing_ok=True)
        # Best-effort cleanup inside container.
        subprocess.run(
            ["docker", "exec", CONTAINER, "rm", "-f", container_prompt_file],
            capture_output=True,
        )


def _scan(path: Path) -> tuple[bool, str]:
    """Run the scanner on the report file. Returns (ok, reason)."""
    from scanner.regex import scan_file

    return scan_file(path)


mcp = FastMCP("research-agent")


@mcp.tool()
def research(prompt: str) -> dict:
    """Run a web-research task in the isolated agent and return the report path.

    Args:
        prompt: The research question or instructions for the agent.

    Returns:
        On success: {"status": "done", "report_path": str}.
        On failure: {"status": "error", "error": str}.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_id = uuid.uuid4().hex
    # Pre-create the destination file so bwrap can bind it into the jail.
    report_path = REPORTS_DIR / f"{report_id}.md"
    report_path.touch()

    try:
        code, output = _run_agent(prompt, report_id)
    except subprocess.TimeoutExpired:
        report_path.unlink(missing_ok=True)
        return {"status": "error", "error": f"agent timeout after {AGENT_TIMEOUT}s"}
    except FileNotFoundError as e:
        report_path.unlink(missing_ok=True)
        return {"status": "error", "error": f"docker not available: {e}"}

    if report_path.stat().st_size == 0:
        report_path.unlink(missing_ok=True)
        return {
            "status": "error",
            "error": f"agent produced no report (exit={code})\n{output[-500:]}",
        }

    ok, reason = _scan(report_path)
    if not ok:
        # Keep scan-failed reports out of the reports dir; move to a quarantine
        # subdir for audit rather than silent delete.
        quarantine = REPORTS_DIR / "_quarantine"
        quarantine.mkdir(exist_ok=True)
        shutil.move(str(report_path), str(quarantine / f"{report_id}.md"))
        return {"status": "error", "error": f"scanner rejected report: {reason}"}

    return {"status": "done", "report_path": str(report_path)}


if __name__ == "__main__":
    mcp.run()
