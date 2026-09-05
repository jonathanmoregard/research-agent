"""Lazy boot: scanner warmup moved off the MCP pre-handshake path.

`main()` must reach `mcp.run()` without waiting on any network I/O — the
client enforces a hard 30 s startup deadline and the old boot path
(`_maybe_update_scanner` + `_boot_smoke`) spent p90 ~10 s / max ~22 s of it
before stdio was ever bound.

Because warmup now races the first tool call, the fail-closed guarantee has
to hold from t=0: `_SCANNER_HEALTH` starts degraded ("warming up") and only
a passing warmup smoke flips it healthy.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import mcp_server.server as server

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _boom(*a, **k):
    raise AssertionError("must not be called")


@pytest.fixture(autouse=True)
def _restore_module_state():
    """Leave the module in a settled, healthy, warmup-finished state so this
    file cannot slow down or destabilise the rest of the suite."""
    yield
    server._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    server._SCANNER_WARMUP_DONE.set()


def _pre_warmup():
    """Module state as it is at import, before the warmup thread resolves."""
    server._SCANNER_WARMUP_DONE.clear()
    server._SCANNER_HEALTH.update(ok=False, reason="warming up", last_check=0.0)


def _stale_last_check() -> float:
    """A monotonic timestamp old enough that any admissible recheck interval
    has already elapsed.

    Not 0.0: `time.monotonic()` is CLOCK_MONOTONIC, which on Linux counts
    from boot. On a fresh CI microVM or container 0.0 is roughly *now*, so
    the throttle is not bypassed, the probe never runs, and the case fails
    for a reason that has nothing to do with the code under test. Same
    helper as tests/test_scanner_health_gate.py.
    """
    return time.monotonic() - 86_400.0


# --- (a) fail-closed from t=0 ------------------------------------------------


def test_scanner_health_starts_degraded_in_a_fresh_process():
    """A fresh import must not present a healthy scanner. Checked in a
    subprocess because every other test in the suite mutates the live dict."""
    code = (
        "import json, mcp_server.server as s; "
        "print('RESULT' + json.dumps([s._SCANNER_HEALTH['ok'], "
        "s._SCANNER_HEALTH['reason'], s._SCANNER_WARMUP_DONE.is_set()]))"
    )
    env = dict(os.environ, PYTHONPATH=str(_REPO_ROOT))
    r = subprocess.run(
        [sys.executable, "-c", code],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
    )
    assert r.returncode == 0, r.stderr
    line = next(ln for ln in r.stdout.splitlines() if ln.startswith("RESULT"))
    ok, reason, warmup_done = json.loads(line[len("RESULT"):])
    assert ok is False, "scanner must start degraded — warmup races the first call"
    assert reason == "warming up"
    assert warmup_done is False


# --- (b) research() refused while warming ------------------------------------


def test_research_refused_while_warming_up(monkeypatch):
    _pre_warmup()
    # Bound the gate's wait so the test does not sit out the real budget.
    monkeypatch.setattr(server, "_SCANNER_WARMUP_WAIT_SECS", 0.05)
    monkeypatch.setattr(server, "_run_agent", _boom)
    monkeypatch.setattr(server, "_run_boot_smoke_once", _boom)

    out = server.research("anything", depth="normal")

    assert out["status"] == "error"
    assert "warming up" in out["error"]


def test_gate_waits_for_a_warmup_that_lands_mid_call(monkeypatch):
    """The common case: the first research() arrives while warmup is still
    running. It should block for the result, not refuse."""
    _pre_warmup()
    monkeypatch.setattr(server, "_SCANNER_WARMUP_WAIT_SECS", 10.0)

    def _late_warmup():
        time.sleep(0.2)
        server._SCANNER_HEALTH.update(ok=True, reason="", last_check=time.monotonic())
        server._SCANNER_WARMUP_DONE.set()

    threading.Thread(target=_late_warmup, daemon=True).start()
    ok, reason = server._scanner_health_gate()

    assert ok is True and reason == ""


# --- (c) passing warmup heals ------------------------------------------------


def test_passing_warmup_flips_health_to_ok(monkeypatch):
    _pre_warmup()
    calls = []
    monkeypatch.setattr(server, "_maybe_update_scanner", lambda: calls.append("update"))
    monkeypatch.setattr(
        server, "_run_boot_smoke_once", lambda: (calls.append("smoke"), (True, ""))[1]
    )

    server._scanner_warmup()

    assert calls == ["update", "smoke"], "update must precede the smoke it validates"
    assert server._SCANNER_HEALTH["ok"] is True
    assert server._SCANNER_WARMUP_DONE.is_set()


def test_warmup_sets_the_done_event_even_when_the_update_raises(monkeypatch):
    """A crashing updater must not strand every later gate call on the wait."""
    _pre_warmup()
    monkeypatch.setattr(server, "_maybe_update_scanner", _boom)
    monkeypatch.setattr(server, "_run_boot_smoke_once", lambda: (True, ""))

    server._scanner_warmup()

    assert server._SCANNER_WARMUP_DONE.is_set()
    assert server._SCANNER_HEALTH["ok"] is True


def test_warmup_stays_degraded_when_the_smoke_import_raises(monkeypatch):
    """An unimportable scanner is an unavailable scanner: fail closed."""
    _pre_warmup()
    monkeypatch.setattr(server, "_maybe_update_scanner", lambda: None)
    monkeypatch.setattr(server, "_run_boot_smoke_once", _boom)

    server._scanner_warmup()

    assert server._SCANNER_WARMUP_DONE.is_set()
    assert server._SCANNER_HEALTH["ok"] is False


# --- (d) failing warmup keeps research() refused -----------------------------


def test_failing_warmup_leaves_research_refused(monkeypatch):
    _pre_warmup()
    monkeypatch.setattr(server, "_maybe_update_scanner", lambda: None)
    monkeypatch.setattr(
        server, "_run_boot_smoke_once", lambda: (False, "lakera_unavailable:no-key")
    )
    server._scanner_warmup()
    monkeypatch.setattr(server, "_run_agent", _boom)

    assert server._SCANNER_HEALTH["ok"] is False
    out = server.research("anything", depth="normal")
    assert out["status"] == "error"
    assert "lakera_unavailable:no-key" in out["error"]


# --- (e) no concurrent double-smoke ------------------------------------------


class _OverlapProbe:
    """Records whether two callers were ever inside the smoke at once."""

    def __init__(self, result=(True, ""), dwell=0.2):
        self._lock = threading.Lock()
        self._inside = 0
        self._result = result
        self._dwell = dwell
        self.runs = 0
        self.overlapped = False

    def __call__(self):
        with self._lock:
            self._inside += 1
            self.runs += 1
            if self._inside > 1:
                self.overlapped = True
        time.sleep(self._dwell)
        with self._lock:
            self._inside -= 1
        return self._result


def test_warmup_and_gate_never_smoke_concurrently(monkeypatch):
    _pre_warmup()
    probe = _OverlapProbe()
    monkeypatch.setattr(server, "_maybe_update_scanner", lambda: None)
    monkeypatch.setattr(server, "_run_boot_smoke_once", probe)
    monkeypatch.setattr(server, "_SCANNER_WARMUP_WAIT_SECS", 10.0)

    results = []
    warm = threading.Thread(target=server._scanner_warmup, daemon=True)
    gate = threading.Thread(
        target=lambda: results.append(server._scanner_health_gate()), daemon=True
    )
    warm.start()
    gate.start()
    warm.join(20)
    gate.join(20)

    assert probe.overlapped is False
    assert probe.runs == 1, "the gate must reuse the warmup's fresh result"
    assert results == [(True, "")]


def test_two_concurrent_gate_rechecks_smoke_once(monkeypatch):
    """Two research() calls arriving together past the recheck throttle must
    not each pay for a smoke, nor interleave writes to _SCANNER_HEALTH."""
    server._SCANNER_WARMUP_DONE.set()
    server._SCANNER_HEALTH.update(
        ok=False, reason="degraded", last_check=_stale_last_check()
    )
    probe = _OverlapProbe()
    monkeypatch.setattr(server, "_run_boot_smoke_once", probe)

    results = []
    threads = [
        threading.Thread(
            target=lambda: results.append(server._scanner_health_gate()), daemon=True
        )
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)

    assert probe.overlapped is False
    assert probe.runs == 1
    assert results == [(True, ""), (True, "")]


# --- (f) main() binds stdio immediately --------------------------------------


def _main_with_blocked_warmup(monkeypatch):
    """Run main() with a warmup that never finishes. Returns (ran, started,
    release, thread); the caller must set `release`."""
    _pre_warmup()
    started, release, ran = threading.Event(), threading.Event(), threading.Event()

    def _blocking_warmup():
        started.set()
        release.wait(30)

    monkeypatch.setattr(server, "_scanner_warmup", _blocking_warmup)
    monkeypatch.setattr(server, "_log_credentials_state", lambda: None)
    # Nothing that touches the network may run on main()'s own thread.
    monkeypatch.setattr(server, "_maybe_update_scanner", _boom)
    monkeypatch.setattr(server, "_boot_smoke", _boom)
    monkeypatch.setattr(server.mcp, "run", lambda: ran.set())

    t = threading.Thread(target=server.main, daemon=True)
    t.start()
    return ran, started, release, t


def test_main_binds_stdio_without_waiting_for_warmup(monkeypatch):
    ran, started, release, t = _main_with_blocked_warmup(monkeypatch)
    try:
        assert ran.wait(10), (
            "main() did not reach mcp.run() while warmup was pending — "
            "slow boot work is still on the pre-handshake path"
        )
        assert started.wait(10), "warmup was never started"
    finally:
        release.set()
        t.join(10)


def test_main_runs_warmup_in_a_daemon_thread(monkeypatch):
    ran, started, release, t = _main_with_blocked_warmup(monkeypatch)
    try:
        assert started.wait(10), "warmup was never started"
        warmers = [x for x in threading.enumerate() if x.name == "scanner-warmup"]
        assert warmers, "warmup thread should be named 'scanner-warmup'"
        assert all(x.daemon for x in warmers), (
            "a non-daemon warmup thread would keep the process alive after "
            "mcp.run() returns"
        )
    finally:
        release.set()
        t.join(10)
