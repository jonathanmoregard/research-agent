"""Cross-process VM lock: research() serializes normal/deep calls, the
fast path is never gated, and an unavailable lock returns a clean busy
error instead of hanging."""
from __future__ import annotations

import multiprocessing
import time

import pytest

import mcp_server.server as server


@pytest.fixture
def lockfile(tmp_path, monkeypatch):
    p = tmp_path / "agent.lock"
    monkeypatch.setattr(server, "_VM_LOCK_PATH", p)
    return p


def test_vm_lock_is_mutually_exclusive(lockfile):
    # Two _vm_lock holders in-process: the second must fail fast with _VMBusy
    # while the first still holds it.
    with server._vm_lock(5):
        with pytest.raises(server._VMBusy):
            with server._vm_lock(0):  # zero wait -> immediate busy
                pass


def test_vm_lock_released_allows_reacquire(lockfile):
    with server._vm_lock(5):
        pass
    # Released — a fresh acquire must succeed immediately.
    with server._vm_lock(1):
        pass


def _hold_lock(path_str, hold_s, ready, released):
    import mcp_server.server as s
    from pathlib import Path
    s._VM_LOCK_PATH = Path(path_str)
    with s._vm_lock(5):
        ready.set()
        time.sleep(hold_s)
    released.set()


def test_vm_lock_blocks_across_processes(lockfile):
    # A separate PROCESS holds the lock; an in-process acquire with a short
    # wait must time out (proves the lock is cross-process, not thread-local).
    ctx = multiprocessing.get_context("fork")
    ready, released = ctx.Event(), ctx.Event()
    proc = ctx.Process(target=_hold_lock, args=(str(lockfile), 3, ready, released))
    proc.start()
    try:
        assert ready.wait(10), "child never acquired the lock"
        # Child holds it for 3s; a 1s-bounded acquire here must raise _VMBusy.
        with pytest.raises(server._VMBusy):
            with server._vm_lock(1):
                pass
    finally:
        proc.join(10)
    assert released.is_set()


def test_research_busy_returns_clean_error(lockfile, monkeypatch):
    # Hold the lock, then call research(normal): it must return the busy
    # error without ever invoking the agent.
    monkeypatch.setattr(server, "_VM_LOCK_WAIT_SECS", 0)
    monkeypatch.setattr(server, "_scanner_health_gate", lambda: (True, ""))

    def _boom(*a, **k):
        raise AssertionError("agent must not run when the VM lock is busy")

    monkeypatch.setattr(server, "_run_agent", _boom)
    with server._vm_lock(5):  # occupy the lock
        out = server.research("q", depth="normal")
    assert out["status"] == "error"
    assert "busy" in out["error"]


def test_fast_path_not_gated_by_lock(lockfile, monkeypatch):
    # depth=fast never touches the VM, so it must succeed even while the
    # lock is held by someone else.
    monkeypatch.setattr(server, "_scanner_health_gate", lambda: (True, ""))
    monkeypatch.setattr(server, "_direct_exa", lambda prompt: (True, "# fast\nok"))

    def _deliver(content, report_id, prompt, agent_ms, t_received, t_scan_start):
        return {"status": "done", "report_path": "x", "report": content}

    monkeypatch.setattr(server, "_scan_and_deliver", _deliver)
    with server._vm_lock(5):  # VM lock held
        out = server.research("q", depth="fast")
    assert out["status"] == "done"
