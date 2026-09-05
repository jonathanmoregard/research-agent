"""Scanner health gate: a failed boot smoke degrades the server instead
of killing it, research() refuses fail-closed while degraded, and the
gate auto-heals on recovery without a reconnect."""
from __future__ import annotations

import mcp_server.server as server


def _reset_health():
    server._SCANNER_HEALTH.update(ok=True, reason="", last_check=0.0)
    # These cases are all about steady-state behaviour, after the background
    # warmup has resolved. Without this the gate would (correctly) sit on
    # _SCANNER_WARMUP_WAIT_SECS waiting for a warmup that never runs here.
    # Warmup-window behaviour is covered by tests/test_lazy_boot_warmup.py.
    server._SCANNER_WARMUP_DONE.set()


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
    server._SCANNER_HEALTH.update(ok=False, reason="honeypot_unavailable:x", last_check=0.0)
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
