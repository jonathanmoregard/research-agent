"""The per-PID protocol marker that gate G3 reads (§12.6 step 3).

New server.py writes $XDG_RUNTIME_DIR/research-agent-mcp/<pid> at start,
whatever egress mode it will pick, and removes it on clean exit. The
question G3 asks is "is this live process running new code?", so a marker
counts as live only if its PID is still a running research-agent MCP
process AND is the same process that wrote it: the marker carries the
process's kernel start time, so a recycled PID reads as stale, not new.

Classification is tested against a fake /proc tree; writing and removal
against this test process's real /proc entry.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import mcp_server.server as srv
from mcp_server import mcp_marker

# The real one: conftest points default_dir away from /run/user for every test.
_REAL_DEFAULT_DIR = mcp_marker.default_dir

MCP_ARGV = [b"/nix/store/x-python3/bin/python3", b"-m", b"mcp_server.server"]
BOOTSTRAP_ARGV = [b"/nix/store/x-python3/bin/python3", b"/nix/store/y-research-agent-mcp-bootstrap.py"]


def _proc(root: Path, pid: int, start: int, argv) -> None:
    d = root / str(pid)
    d.mkdir(parents=True)
    # comm may hold spaces and parens; starttime is field 22 overall.
    tail = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 30
    (d / "stat").write_text(f"{pid} (python3 (x) y) " + " ".join(tail) + "\n")
    (d / "cmdline").write_bytes(b"\0".join(argv) + b"\0")


@pytest.fixture
def tree(tmp_path):
    proc, markers = tmp_path / "proc", tmp_path / "markers"
    proc.mkdir()
    markers.mkdir(mode=0o700)
    return proc, markers


def test_a_marker_of_its_own_running_mcp_process_is_live(tree):
    proc, markers = tree
    _proc(proc, 4242, 777, MCP_ARGV)
    (markers / "4242").write_text("777\n")
    assert mcp_marker.classify("4242", markers, proc) == "live"


def test_the_bootstrap_launch_counts_as_an_mcp_process(tree):
    proc, markers = tree
    _proc(proc, 4243, 9, BOOTSTRAP_ARGV)
    (markers / "4243").write_text("9\n")
    assert mcp_marker.classify("4243", markers, proc) == "live"


def test_a_marker_whose_process_is_gone_is_stale(tree):
    proc, markers = tree
    (markers / "4242").write_text("777\n")  # killed: no clean-exit removal
    assert mcp_marker.classify("4242", markers, proc) == "stale"


def test_a_marker_whose_pid_is_now_something_else_is_stale(tree):
    proc, markers = tree
    _proc(proc, 4242, 777, [b"/usr/bin/bash", b"-c", b"sleep 1"])
    (markers / "4242").write_text("777\n")
    assert mcp_marker.classify("4242", markers, proc) == "stale"


def test_a_recycled_pid_is_stale_even_if_it_is_an_mcp_process_again(tree):
    """A pre-pull MCP that got the dead new-code process's PID must not
    pass G3 on the old marker."""
    proc, markers = tree
    _proc(proc, 4242, 999, MCP_ARGV)  # a later process, same PID
    (markers / "4242").write_text("777\n")
    assert mcp_marker.classify("4242", markers, proc) == "stale"


@pytest.mark.parametrize("content", ["", "abc\n", "777 888\n"])
def test_an_unreadable_marker_is_stale(tree, content):
    proc, markers = tree
    _proc(proc, 4242, 777, MCP_ARGV)
    (markers / "4242").write_text(content)
    assert mcp_marker.classify("4242", markers, proc) == "stale"


def test_live_lists_live_markers_only_and_sweep_removes_stale_ones(tree):
    proc, markers = tree
    _proc(proc, 10, 1, MCP_ARGV)
    _proc(proc, 11, 5, MCP_ARGV)
    (markers / "10").write_text("1\n")   # live
    (markers / "11").write_text("4\n")   # recycled
    (markers / "12").write_text("1\n")   # gone
    (markers / "notapid").write_text("1\n")
    assert mcp_marker.live(markers, proc) == ["10"]
    mcp_marker.sweep(markers, proc)
    assert sorted(p.name for p in markers.iterdir()) == ["10", "notapid"]


def test_write_records_this_process_and_remove_takes_it_away(tmp_path):
    d = tmp_path / "run" / "research-agent-mcp"
    path = mcp_marker.write(d)
    assert path == d / str(os.getpid())
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert int(path.read_text()) == mcp_marker.start_ticks(os.getpid())
    mcp_marker.remove(path)
    assert not path.exists()


def test_remove_leaves_a_marker_another_process_wrote(tmp_path):
    d = tmp_path / "m"
    path = mcp_marker.write(d)
    path.write_text("1\n")  # not ours any more
    mcp_marker.remove(path)
    assert path.exists()


def test_write_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    assert mcp_marker.write(blocker / "sub") is None  # a server must still start


def test_marker_dir_is_the_user_runtime_dir(monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert _REAL_DEFAULT_DIR() == Path("/run/user/1000/research-agent-mcp")
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    assert _REAL_DEFAULT_DIR() == Path(f"/run/user/{os.getuid()}/research-agent-mcp")


def test_main_writes_the_marker_before_serving_whatever_the_egress_era(
        tmp_path, monkeypatch):
    """Unconditional: the conftest leaves no era file (a pre-broker host),
    and the marker is still there by the time the server binds stdio."""
    d = tmp_path / "markers"
    monkeypatch.setattr(mcp_marker, "default_dir", lambda: d)
    seen = {}
    monkeypatch.setattr(srv, "_log_credentials_state", lambda: None)
    monkeypatch.setattr(srv, "_scanner_warmup", lambda: None)
    monkeypatch.setattr(srv.mcp, "run", lambda: seen.update(
        exists=(d / str(os.getpid())).exists()))
    registered = []
    monkeypatch.setattr(srv.atexit, "register", lambda fn, *a: registered.append((fn, a)))
    srv.main()
    assert seen == {"exists": True}
    # Clean exit removes it (the atexit hook main() registered).
    for fn, a in registered:
        fn(*a)
    assert not (d / str(os.getpid())).exists()
