"""research() holds its run open at the scraper while it can still collect.

The scraper's roll waits for `pending_artifacts == 0`, which counts only
artifacts a live run could still pull (§12.3). research() is the only
collector of a run's screenshots, so it tells the scraper it is alive by
holding `POST /artifacts/<run>/hold` open from before the agent starts until
it returns, on every exit path. If its process dies, the kernel closes the
socket: no clock decides that a run is gone.

The scraper is a loopback stub implementing the hold the way
scraper/server.py does (reply, then wait for EOF).
"""
from __future__ import annotations

import http.server
import json
import re
import socket
import threading
import time

import pytest

import mcp_server.server as srv
from mcp_server import artifact_gate

BEARER = "hold-bearer-for-tests"


class HoldScraper(http.server.ThreadingHTTPServer):
    def __init__(self):
        self.events: list[tuple[str, str]] = []
        stub = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                m = re.match(r"^/artifacts/([a-f0-9]{32})/hold$", self.path)
                if not m or self.headers.get("Authorization") != f"Bearer {BEARER}":
                    self.send_response(403)
                    self.end_headers()
                    return
                data = json.dumps({"status": "ok", "holding": m.group(1)}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                stub.events.append(("open", m.group(1)))
                self.connection.settimeout(None)
                try:  # FIN reads as EOF; a close with our reply unread is a RST
                    while self.rfile.read(1):
                        pass
                except OSError:
                    pass
                stub.events.append(("closed", m.group(1)))

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()


def _until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not pred() and time.monotonic() < deadline:
        time.sleep(0.02)
    return pred()


class _Lock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def scraper(tmp_path, monkeypatch):
    stub = HoldScraper()
    token = tmp_path / "bearer"
    token.write_text(BEARER + "\n")
    monkeypatch.setattr(artifact_gate, "SCRAPER_HOST_API", f"http://127.0.0.1:{stub.server_port}")
    monkeypatch.setattr(artifact_gate, "SCRAPER_HOST_TOKEN_FILE", str(token))
    monkeypatch.setattr(srv, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(srv, "_vm_lock", lambda *a, **k: _Lock())
    monkeypatch.setattr(srv, "_scanner_health_gate", lambda: (True, ""))
    yield stub
    stub.shutdown()
    stub.server_close()


def test_the_run_is_held_while_the_agent_runs_and_released_on_return(scraper, monkeypatch):
    seen = {}

    def agent(prompt, report_id, depth, model):
        seen["id"] = report_id
        seen["held"] = _until(lambda: ("open", report_id) in scraper.events)
        return 1, "agent crashed"

    monkeypatch.setattr(srv, "_run_agent", agent)
    out = srv.research("a question", depth="normal")
    assert out["error"] == "agent failed"  # an early return that never pulls
    assert seen["held"], "the hold must be in place before the agent can save"
    assert _until(lambda: ("closed", seen["id"]) in scraper.events), \
        "research() returned: the run's artifacts are orphans now"


def test_the_hold_is_released_when_the_call_raises(scraper, monkeypatch):
    seen = {}

    def agent(prompt, report_id, depth, model):
        seen["id"] = report_id
        raise RuntimeError("boom")

    monkeypatch.setattr(srv, "_run_agent", agent)
    out = srv.research("a question", depth="normal")
    assert out["error"] == "agent invocation failed"
    assert _until(lambda: ("closed", seen["id"]) in scraper.events)


def test_an_unreachable_scraper_never_fails_research(scraper, monkeypatch):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens
    monkeypatch.setattr(artifact_gate, "SCRAPER_HOST_API", f"http://127.0.0.1:{port}")
    ran = []
    monkeypatch.setattr(srv, "_run_agent", lambda *a: ran.append(1) or (1, ""))
    out = srv.research("a question", depth="normal")
    assert ran and out["error"] == "agent failed"


def test_the_fast_path_holds_nothing(scraper, monkeypatch):
    """depth=fast is a direct Exa call: no browser, no artifacts to collect."""
    monkeypatch.setattr(srv, "_direct_exa", lambda p: (False, "direct: exa call failed"))
    srv.research("a question", depth="fast")
    time.sleep(0.2)
    assert scraper.events == []
