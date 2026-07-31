"""Cross-process VM admission control: research() admits at most
`_VM_SLOTS` normal/deep calls at once, the fast path is never gated, and
an exhausted slot set returns a clean busy error instead of hanging.

Most tests pin `_VM_SLOTS` to 1 — the strictest setting, where the
semaphore must behave exactly like the exclusive lock it replaced.
Multi-slot behaviour is covered separately below."""
from __future__ import annotations

import multiprocessing
import time

import pytest

import mcp_server.server as server


@pytest.fixture
def lockfile(tmp_path, monkeypatch):
    p = tmp_path / "agent.lock"
    monkeypatch.setattr(server, "_VM_LOCK_PATH", p)
    monkeypatch.setattr(server, "_VM_SLOTS", 1)
    return p


@pytest.fixture
def slots(tmp_path, monkeypatch):
    """Parameterisable slot count sharing one lock-file base path."""
    def _set(n):
        monkeypatch.setattr(server, "_VM_LOCK_PATH", tmp_path / "agent.lock")
        monkeypatch.setattr(server, "_VM_SLOTS", n)
    return _set


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


def _hold_lock(path_str, hold_s, ready, released, slots=1):
    import mcp_server.server as s
    from pathlib import Path
    s._VM_LOCK_PATH = Path(path_str)
    s._VM_SLOTS = slots
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


# --- multi-slot admission control -------------------------------------
#
# Sizing rationale lives next to _VM_SLOTS in server.py; measured
# 2026-07-31: two concurrent deep calls peaked at 1.57 GB of a 6 GB
# guest, so a default of 3 has ample headroom.


def test_n_slots_admit_n_concurrent_callers(slots):
    slots(3)
    with server._vm_lock(1), server._vm_lock(1), server._vm_lock(1):
        pass  # three simultaneous holders must all be admitted


def test_caller_n_plus_one_gets_busy(slots):
    slots(2)
    with server._vm_lock(1), server._vm_lock(1):
        with pytest.raises(server._VMBusy):
            with server._vm_lock(0):
                pass


def test_freed_slot_is_reused(slots):
    """Releasing one of N holders must let the next caller straight in —
    a leaked fd or a slot pinned to the wrong index would hang instead."""
    slots(2)
    with server._vm_lock(1):
        with server._vm_lock(1):
            pass
        with server._vm_lock(0):  # second slot free again
            pass


def test_slot_released_when_body_raises(slots):
    slots(1)
    with pytest.raises(ValueError):
        with server._vm_lock(1):
            raise ValueError("boom")
    with server._vm_lock(0):  # slot must not have leaked
        pass


def test_slots_are_cross_process(slots, tmp_path):
    """One slot, held by another PROCESS: proves admission is kernel-level
    (flock), not thread-local state."""
    slots(1)
    ctx = multiprocessing.get_context("fork")
    ready, released = ctx.Event(), ctx.Event()
    proc = ctx.Process(
        target=_hold_lock, args=(str(tmp_path / "agent.lock"), 3, ready, released, 1)
    )
    proc.start()
    try:
        assert ready.wait(10), "child never acquired a slot"
        with pytest.raises(server._VMBusy):
            with server._vm_lock(1):
                pass
    finally:
        proc.join(10)
    assert released.is_set()


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, server._VM_SLOTS_DEFAULT),
        ("", server._VM_SLOTS_DEFAULT),
        ("4", 4),
        ("1", 1),
        ("0", 1),        # 0 would make every call busy — clamp
        ("-3", 1),
        ("banana", server._VM_SLOTS_DEFAULT),  # never crash at import
    ],
)
def test_read_slots_parsing(raw, expected):
    assert server._read_slots(raw) == expected
