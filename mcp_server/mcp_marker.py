"""Per-PID protocol marker for gate G3 (docs/egress-broker.md §12.6 step 3).

Every server.py from the dual-mode release on writes
`$XDG_RUNTIME_DIR/research-agent-mcp/<pid>` at start, whatever egress mode
it will pick, and removes it on clean exit. nixos-A's
`research-mcp-protocheck` reads it to answer "is every live MCP process
running new code?": a pre-pull process writes none, so it is legacy-capable.

The marker holds the process's kernel start time (field 22 of
/proc/<pid>/stat, clock ticks since boot). A marker is live only while
/proc/<pid> exists, is a research-agent MCP process, and started at that
same tick: a killed process leaves a stale marker, and a recycled PID (on a
long-running host) does not inherit it. /run/user is a tmpfs, so ticks
never have to survive a reboot.

Stdlib only; never raises into the server, which must start regardless.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

DIRNAME = "research-agent-mcp"


def default_dir() -> Path:
    run = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return Path(run) / DIRNAME


def start_ticks(pid: int | str, proc: str | Path = "/proc") -> int | None:
    try:
        with open(Path(proc) / str(pid) / "stat", encoding="ascii", errors="replace") as f:
            # comm (field 2) may contain spaces and parens: split after the last ')'.
            return int(f.read().rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None


def is_mcp(argv: list[bytes]) -> bool:
    """The process shapes nixos launches (same test as protocheck)."""
    if not argv or not os.path.basename(argv[0]).startswith(b"python"):
        return False
    if any(a.endswith(b"research-agent-mcp-bootstrap.py") for a in argv):
        return True
    return any(a == b"-m" and b == b"mcp_server.server" for a, b in zip(argv, argv[1:]))


def _argv(pid: str, proc: Path) -> list[bytes]:
    try:
        with open(proc / pid / "cmdline", "rb") as f:
            return [a for a in f.read().split(b"\0") if a]
    except OSError:
        return []


def classify(pid: str, directory: str | Path, proc: str | Path = "/proc") -> str:
    """"live" or "stale" for the marker named `pid` in `directory`."""
    proc = Path(proc)
    try:
        recorded = int((Path(directory) / pid).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return "stale"
    ticks = start_ticks(pid, proc)
    if ticks is None or ticks != recorded or not is_mcp(_argv(pid, proc)):
        return "stale"
    return "live"


def _markers(directory: Path) -> list[str]:
    try:
        return sorted((n for n in os.listdir(directory) if n.isdigit()), key=int)
    except OSError:
        return []


def live(directory: str | Path, proc: str | Path = "/proc") -> list[str]:
    return [p for p in _markers(Path(directory)) if classify(p, directory, proc) == "live"]


def sweep(directory: str | Path, proc: str | Path = "/proc") -> None:
    """Remove stale markers (killed processes never remove their own)."""
    for pid in _markers(Path(directory)):
        if classify(pid, directory, proc) == "stale":
            try:
                os.unlink(Path(directory) / pid)
            except OSError:
                pass


def write(directory: str | Path | None = None) -> Path | None:
    """Mark this process. Returns the marker path, or None on any failure."""
    try:
        d = Path(directory) if directory is not None else default_dir()
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        pid = os.getpid()
        ticks = start_ticks(pid)
        if ticks is None:
            raise OSError("no /proc start time")
        sweep(d)
        path = d / str(pid)
        tmp = d / f".{pid}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(f"{ticks}\n")
        os.replace(tmp, path)
        return path
    except Exception as e:
        print(f"research-agent: protocol marker not written: {type(e).__name__}",
              file=sys.stderr)
        return None


def remove(path: Path | None) -> None:
    """Clean exit: remove our marker, never one a later process wrote."""
    if path is None:
        return
    try:
        if int(path.read_text(encoding="ascii").strip()) == start_ticks(os.getpid()):
            os.unlink(path)
    except (OSError, ValueError):
        pass
