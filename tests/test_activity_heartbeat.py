"""Activity heartbeat: the MCP touches a file while a research call is
live so the host watchdog can tell 'busy' from 'dead'."""
from __future__ import annotations

import time

import mcp_server.server as server


def test_heartbeat_touches_then_clears(tmp_path, monkeypatch):
    f = tmp_path / "active"
    monkeypatch.setattr(server, "_ACTIVITY_FILE", f)
    assert not f.exists()
    with server._activity_heartbeat():
        # Touched immediately on entry.
        assert f.exists()
    # Cleared on exit so the watchdog resumes at once.
    assert not f.exists()


def test_heartbeat_refreshes_mtime(tmp_path, monkeypatch):
    f = tmp_path / "active"
    monkeypatch.setattr(server, "_ACTIVITY_FILE", f)
    monkeypatch.setattr(server, "_HEARTBEAT_INTERVAL_S", 0)  # refresh as fast as possible
    with server._activity_heartbeat():
        assert f.exists()
        m1 = f.stat().st_mtime_ns
        time.sleep(0.05)
        server._touch_activity()  # deterministic refresh
        m2 = f.stat().st_mtime_ns
        assert m2 >= m1


def test_touch_activity_never_raises(tmp_path, monkeypatch):
    # A non-writable parent must not blow up a research call.
    bad = tmp_path / "nope" / "deeper"
    monkeypatch.setattr(server, "_ACTIVITY_FILE", bad / "active")
    # Make mkdir fail by pointing at a path under a file.
    (tmp_path / "nope").write_text("i am a file, not a dir")
    server._touch_activity()  # must not raise


def test_heartbeat_thread_stops_on_exit(tmp_path, monkeypatch):
    f = tmp_path / "active"
    monkeypatch.setattr(server, "_ACTIVITY_FILE", f)
    monkeypatch.setattr(server, "_HEARTBEAT_INTERVAL_S", 0)
    with server._activity_heartbeat():
        pass
    # No live heartbeat threads named research-heartbeat after exit.
    import threading
    time.sleep(0.05)
    alive = [t for t in threading.enumerate() if t.name == "research-heartbeat" and t.is_alive()]
    assert alive == []
