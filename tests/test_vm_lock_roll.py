"""§12.7: a call that arrives during a drained roll waits it out.

The roll (nixos-A `research-vm-roll@`) holds every slot and touches
/run/research-agent/rolling while it restarts a microVM. A call's own lock
wait (_VM_LOCK_WAIT_SECS, 1800 s) must not be spent against the roll: while
the marker exists the wait extends, so the call is delayed, not failed. A
ceiling still bounds it, because a roll that times out at its ready check
(§12.3 step 7) keeps the marker AND the slots; a call that then hangs
forever is worse than one that fails with a clear reason.

Times are scaled down (base wait, ceiling and release grace are module
inputs); the shape is the production one: base < ceiling.
"""
from __future__ import annotations

import threading
import time

import pytest

import mcp_server.server as server

BASE, CEILING, GRACE = 0.3, 1.5, 0.4


@pytest.fixture
def roll(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_VM_LOCK_PATH", tmp_path / "agent.lock")
    monkeypatch.setattr(server, "_VM_SLOTS", 1)
    marker = tmp_path / "rolling"
    monkeypatch.setattr(server, "_ROLL_MARKER_PATH", marker)
    monkeypatch.setattr(server, "_ROLL_WAIT_CEILING_SECS", CEILING)
    monkeypatch.setattr(server, "_ROLL_RELEASE_GRACE_SECS", GRACE)
    return marker


def _roll_holds_slots(marker, unmark_at=None, release_at=None):
    """The roll: every slot held and the marker set; step 6 removes the
    marker, then releases the slots."""
    held, done = threading.Event(), threading.Event()

    def run():
        with server._vm_lock(5):
            marker.touch()
            held.set()
            t0 = time.monotonic()
            if unmark_at is None:
                done.wait(30)
                return
            time.sleep(unmark_at)
            marker.unlink()
            time.sleep(max(0.0, release_at - (time.monotonic() - t0)))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert held.wait(5)
    return t, done


def test_a_call_during_a_roll_waits_past_its_own_budget_and_gets_the_slot(roll):
    t, _ = _roll_holds_slots(roll, unmark_at=0.9, release_at=1.0)
    t0 = time.monotonic()
    with server._vm_lock(BASE):
        waited = time.monotonic() - t0
    t.join(5)
    assert BASE + 0.5 < waited < CEILING, waited  # delayed past BASE, not failed


def test_the_slot_release_just_after_the_marker_goes_is_still_waited_for(roll):
    """Step 6 removes the marker before it releases the locks: a call
    checking in between must not give up."""
    t, _ = _roll_holds_slots(roll, unmark_at=0.5, release_at=0.5 + GRACE / 2)
    with server._vm_lock(BASE):
        pass
    t.join(5)


def test_a_stuck_roll_still_hits_the_ceiling_with_a_clear_reason(roll):
    t, done = _roll_holds_slots(roll)  # step 7: marker and slots stay
    t0 = time.monotonic()
    try:
        with pytest.raises(server._VMBusy) as e:
            with server._vm_lock(BASE):
                pass
        waited = time.monotonic() - t0
    finally:
        done.set()
        t.join(5)
    assert CEILING - 0.05 < waited < CEILING + 1.0, waited
    assert e.value.during_roll


def test_without_a_roll_the_budget_is_unchanged(roll):
    with server._vm_lock(5):
        t0 = time.monotonic()
        with pytest.raises(server._VMBusy) as e:
            with server._vm_lock(BASE):
                pass
        waited = time.monotonic() - t0
    assert waited < BASE + 0.3, waited
    assert not e.value.during_roll


def test_research_names_the_stuck_roll(roll, monkeypatch):
    monkeypatch.setattr(server, "_VM_LOCK_WAIT_SECS", 0)
    monkeypatch.setattr(server, "_ROLL_WAIT_CEILING_SECS", 0.3)
    monkeypatch.setattr(server, "_scanner_health_gate", lambda: (True, ""))
    monkeypatch.setattr(server, "_run_agent", lambda *a: pytest.fail("agent must not run"))
    t, done = _roll_holds_slots(roll)
    try:
        out = server.research("q", depth="normal")
    finally:
        done.set()
        t.join(5)
    assert out["status"] == "error" and "busy" in out["error"]
    assert "roll" in out["error"]


def test_production_ceiling_outlasts_the_call_budget():
    """The ceiling exists to let a call wait PAST its own 1800 s."""
    assert server._ROLL_WAIT_CEILING_SECS > server._VM_LOCK_WAIT_SECS
