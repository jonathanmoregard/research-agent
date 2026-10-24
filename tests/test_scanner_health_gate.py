"""Scanner health gate: a failed boot smoke degrades the server instead
of killing it, research() refuses fail-closed while degraded, and the
gate auto-heals on recovery without a reconnect."""
from __future__ import annotations

import math
import time

import pytest

import mcp_server.server as server


def _reset_health():
    server._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    # These cases are all about steady-state behaviour, after the background
    # warmup has resolved. Without this the gate would (correctly) sit on
    # _SCANNER_WARMUP_WAIT_SECS waiting for a warmup that never runs here.
    # Warmup-window behaviour is covered by tests/test_lazy_boot_warmup.py.
    server._SCANNER_WARMUP_DONE.set()


@pytest.fixture(autouse=True)
def _restore_module_state():
    """Leave the module settled, healthy and warmup-finished so no case here
    can contaminate a later test that calls research() without its own reset.

    `test_gate_throttles_recheck` in particular used to exit leaving
    _SCANNER_HEALTH degraded with a fresh last_check, which refuses every
    later research() that does not reset for itself — order-dependent
    contamination that only shows up when the suite is resharded.

    Same fixture as tests/test_lazy_boot_warmup.py — these two files are the
    only ones that mutate the live scanner-health globals, and they must
    restore identically or the order they happen to run in becomes load
    bearing.
    """
    yield
    server._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    server._SCANNER_WARMUP_DONE.set()


def _stale_last_check() -> float:
    """A monotonic timestamp old enough that any admissible recheck interval
    has already elapsed.

    Not 0.0: `time.monotonic()` is CLOCK_MONOTONIC, which on Linux counts
    from boot. On a fresh CI microVM or container 0.0 is roughly *now*, so
    `now - 0.0 >= _SCANNER_RECHECK_SECS` is False and the throttle is not
    bypassed at all — the probe never runs and the test fails for a reason
    that has nothing to do with the gate.
    """
    return time.monotonic() - 86_400.0


def test_boot_smoke_failure_is_non_fatal(monkeypatch):
    _reset_health()
    monkeypatch.setattr(server, "_run_boot_smoke_once", lambda: (False, "lakera_unavailable:no-key"))
    # Must NOT raise SystemExit — the old behavior forced an MCP reconnect.
    server._boot_smoke()
    assert server._SCANNER_HEALTH["ok"] is False
    assert server._SCANNER_HEALTH["reason"] == "lakera_unavailable:no-key"


def test_research_refused_while_degraded_without_running_agent(monkeypatch):
    _reset_health()
    server._SCANNER_HEALTH.update(ok=False, reason="lakera_unavailable:no-key", last_check=1e18)

    def _boom(*a, **k):
        raise AssertionError("agent must not run while scanner is degraded")

    monkeypatch.setattr(server, "_run_agent", _boom)
    out = server.research("anything", depth="normal")
    assert out["status"] == "error"
    assert "scanner degraded" in out["error"]
    assert "lakera_unavailable:no-key" in out["error"]


def test_gate_auto_heals_after_recheck(monkeypatch):
    _reset_health()
    # Degraded, last check long ago so a re-check is due.
    server._SCANNER_HEALTH.update(
        ok=False, reason="honeypot_unavailable:x", last_check=_stale_last_check()
    )
    monkeypatch.setattr(server, "_run_boot_smoke_once", lambda: (True, ""))
    ok, reason = server._scanner_health_gate()
    assert ok is True
    assert server._SCANNER_HEALTH["ok"] is True


def test_gate_throttles_recheck(monkeypatch):
    _reset_health()
    import time
    server._SCANNER_HEALTH.update(ok=False, reason="degraded", last_check=time.monotonic())
    calls = []
    monkeypatch.setattr(server, "_run_boot_smoke_once", lambda: (calls.append(1), (True, ""))[1])
    ok, _ = server._scanner_health_gate()
    # Recently checked -> no re-run, still degraded.
    assert ok is False
    assert calls == []


def test_healthy_gate_is_noop(monkeypatch):
    _reset_health()
    monkeypatch.setattr(
        server, "_run_boot_smoke_once",
        lambda: (_ for _ in ()).throw(AssertionError("no re-check when healthy")),
    )
    ok, reason = server._scanner_health_gate()
    assert ok is True and reason == ""


# --- tolerant parsing of the seconds knobs -----------------------------------
#
# These are parsed at module scope, before stdio is bound, so a bare float()
# turns an operator typo into a server that dies during the MCP handshake.
# Worse, float() accepts "nan": every comparison against NaN is False, so
# `now - last_check >= nan` never fires and a degraded server silently stops
# self-healing. Mirrors tests/test_vm_lock.py::test_read_slots_parsing.


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, 60.0),        # unset -> documented default
        ("", 60.0),          # `export X=` means "unset", not "force empty"
        ("30", 30.0),
        ("30.5", 30.5),
        ("  45 ", 45.0),
        ("abc", 60.0),       # malformed -> default, never ValueError at import
        ("nan", 60.0),       # parses as a float and then poisons every compare
        ("inf", 60.0),
        ("-inf", 60.0),
        ("1e400", 60.0),     # overflows to inf
        ("0", 1.0),          # a zero interval re-smokes on every single call
        ("-5", 1.0),
        ("999999", 3600.0),  # an absurd interval stops self-healing entirely
    ],
)
def test_read_secs_parsing(raw, expected):
    assert server._read_secs(raw, 60.0, lo=1.0, hi=3600.0, name="X") == expected


def test_scanner_seconds_knobs_are_finite_and_usable():
    """Whatever the environment said, the live constants must be values the
    gate can actually act on — a non-finite recheck interval would leave a
    degraded server refusing forever."""
    assert math.isfinite(server._SCANNER_RECHECK_SECS)
    assert server._SCANNER_RECHECK_SECS > 0
    assert math.isfinite(server._SCANNER_WARMUP_WAIT_SECS)
    assert server._SCANNER_WARMUP_WAIT_SECS >= 0


def test_a_nan_recheck_interval_cannot_wedge_the_gate(monkeypatch):
    """Belt and braces on the clamp: even if a NaN reached the interval, the
    gate must refuse rather than return healthy."""
    _reset_health()
    server._SCANNER_HEALTH.update(
        ok=False, reason="degraded", last_check=_stale_last_check()
    )
    monkeypatch.setattr(server, "_SCANNER_RECHECK_SECS", float("nan"))
    monkeypatch.setattr(server, "_run_boot_smoke_once", lambda: (True, ""))
    ok, _ = server._scanner_health_gate()
    assert ok is False, "a poisoned interval must fail closed, never open"
