"""Scraper GET /health: what the drained roll reads (§12.3 step 1 and 2).

The scraper has the checkout's scraper/ on its share, so it checks its own
code: the digest it loaded, the digest on disk now, and `stale`. The roll
restarts it only when it reports no open sessions and no un-pulled
artifacts. One digest implementation for broker and scraper (scraper/digest.py,
the one directory both services see); /health must never boot the browser.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import sys
import threading
import time
import types
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scraper") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scraper"))

# Same Playwright stub as the other scraper route tests: server.py imports it
# at module level, and no test here may launch a browser.
if "playwright.sync_api" not in sys.modules:
    _pw_sync = types.ModuleType("playwright.sync_api")

    class _StubError(Exception):
        pass

    def _no_playwright(*a, **kw):  # pragma: no cover — never called here
        raise NotImplementedError("test stub")

    _pw_sync.Error = _StubError
    _pw_sync.sync_playwright = _no_playwright
    sys.modules.setdefault("playwright", types.ModuleType("playwright"))
    sys.modules["playwright.sync_api"] = _pw_sync

# The token server.py caches at import: same stub file and content as the other
# scraper route tests, whichever of them imports server first.
_TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
_TOKEN_FILE.write_text("stub-token-for-tests\n")
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

import digest  # noqa: E402  (scraper/digest.py, as the scraper imports it)
import server  # noqa: E402
import sessions  # noqa: E402

RUN = "d" * 32


@pytest.fixture
def health():
    srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                     daemon=True).start()

    def get():
        with urllib.request.urlopen(
                f"http://127.0.0.1:{srv.server_address[1]}/health", timeout=5) as r:
            return r.status, json.loads(r.read())
    get.port = srv.server_address[1]
    yield get
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    """A copy of the scraper code the running server believes it came from."""
    root = tmp_path / "workspace"
    (root / "scraper").mkdir(parents=True)
    for f in (REPO_ROOT / "scraper").glob("*.py"):
        shutil.copyfile(f, root / "scraper" / f.name)
    monkeypatch.setattr(server, "_CHECKOUT", str(root))
    monkeypatch.setattr(server, "_LOADED_DIGEST", digest.scraper_digest(str(root)))
    return root


def test_health_reports_loaded_and_on_disk_digest(health, checkout):
    status, body = health()
    assert status == 200 and body["status"] == "ok"
    assert body["code"] == body["code_on_disk"] == digest.scraper_digest(str(checkout))
    assert body["stale"] is False


def test_health_reports_stale_after_a_pull_changes_scraper_code(health, checkout):
    loaded = health()[1]["code"]
    f = checkout / "scraper" / "sessions.py"
    f.write_text(f.read_text() + "\n# pulled\n")
    status, body = health()
    assert status == 200
    assert body["code"] == loaded, "`code` is what this process loaded, not the disk"
    assert body["code_on_disk"] != loaded
    assert body["stale"] is True


def test_health_digest_is_location_independent(tmp_path):
    other = tmp_path / "elsewhere"
    (other / "scraper").mkdir(parents=True)
    for f in (REPO_ROOT / "scraper").glob("*.py"):
        shutil.copyfile(f, other / "scraper" / f.name)
    assert digest.scraper_digest(str(other)) == digest.scraper_digest(str(REPO_ROOT))


def test_server_loaded_digest_is_its_own_tree():
    assert server._CHECKOUT == str(REPO_ROOT)
    assert server._LOADED_DIGEST == digest.scraper_digest(str(REPO_ROOT))


def test_health_counts_pending_artifacts_until_pulled(health, checkout):
    store = sessions.get_artifact_store()
    store.take(RUN)
    before = health()[1]["pending_artifacts"]
    store.add(RUN, "shot-1", b"\x89PNG-fake", "image/png")
    store.add(RUN, "shot-2", b"\x89PNG-fake", "image/png")
    try:
        assert health()[1]["pending_artifacts"] == before + 2
    finally:
        store.take(RUN)  # what the MCP's pull does
    assert health()[1]["pending_artifacts"] == before


class _FakeBrowser:
    def new_context(self, **kw):
        from tests.test_scraper_sessions import _FakeContext
        return _FakeContext()

    def close(self):
        pass


def test_health_counts_open_sessions(health, checkout, monkeypatch):
    w = sessions.BrowserWorker(browser_factory=_FakeBrowser, idle_ttl_s=9999)
    w.start()
    monkeypatch.setattr(sessions, "_worker", w)
    try:
        assert health()[1]["open_sessions"] == 0
        sid = w.submit({"op": "open", "url": "https://x.test/", "run_id": RUN})["session_id"]
        assert health()[1]["open_sessions"] == 1
        w.submit({"op": "close", "session_id": sid, "run_id": RUN})
        assert health()[1]["open_sessions"] == 0
    finally:
        w.shutdown()


def test_health_never_boots_the_browser_worker(health, checkout, monkeypatch):
    monkeypatch.setattr(sessions, "_worker", None)

    def boom():  # pragma: no cover — the assertion is that this never runs
        raise AssertionError("/health booted the browser worker")
    monkeypatch.setattr(sessions, "get_worker", boom)
    monkeypatch.setattr(server, "get_worker", boom)
    status, body = health()
    assert status == 200 and body["open_sessions"] == 0
    assert sessions._worker is None


def test_broker_and_scraper_share_one_digest_implementation(tmp_path):
    """§12.2/§12.3: one implementation. broker/digest.py only chooses the
    broker's file set; the hashing lives in scraper/digest.py."""
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from broker import digest as broker_digest
        from scraper import digest as shared
    finally:
        sys.path.remove(str(REPO_ROOT))
    src = (REPO_ROOT / "broker" / "digest.py").read_text()
    assert "hashlib" not in src and "sha256" not in src, "a second copy of the hash"
    rels = sorted(f"broker/{p.name}" for p in (REPO_ROOT / "broker").glob("*.py"))
    assert broker_digest.code_digest(str(REPO_ROOT)) == shared.tree_digest(
        str(REPO_ROOT), rels + ["scraper/digest.py", "scraper/urlpolicy.py"])
    rels = sorted(f"scraper/{p.name}" for p in (REPO_ROOT / "scraper").glob("*.py"))
    assert digest.scraper_digest(str(REPO_ROOT)) == shared.tree_digest(str(REPO_ROOT), rels)


# --- pending_artifacts counts only runs that can still be pulled (§12.3) -----------
#
# The MCP's research() call is the only collector of a run's artifacts. It
# holds `POST /artifacts/<run>/hold` open for its whole life; the hold ends
# when the call returns or its process dies (the kernel closes the socket),
# with no clock involved. Artifacts of a run whose hold ended can never be
# pulled: they are orphans, discarded and not counted.

LIVE, DEAD = "a1" * 16, "b2" * 16
BEARER = "Bearer stub-token-for-tests"


def _hold(port, run_id, bearer=BEARER):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(f"POST /artifacts/{run_id}/hold HTTP/1.0\r\nAuthorization: {bearer}\r\n"
              "Content-Length: 0\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    return s, head


def _until(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not pred() and time.monotonic() < deadline:
        time.sleep(0.02)
    return pred()


@pytest.fixture
def store(monkeypatch):
    s = sessions.ArtifactStore()
    monkeypatch.setattr(sessions, "_artifact_store", s)
    return s


@pytest.mark.parametrize("ending", ["fin", "rst"])
def test_pending_artifacts_excludes_an_orphaned_run_and_the_roll_clears(
        health, checkout, store, ending):
    live, head = _hold(health.port, LIVE)
    assert head.startswith(b"HTTP/1.0 200"), head
    dead, head = _hold(health.port, DEAD)
    assert head.startswith(b"HTTP/1.0 200"), head
    try:
        store.add(LIVE, "shot", b"\x89PNG-fake", "image/png")
        store.add(DEAD, "shot", b"\x89PNG-fake", "image/png")
        assert health()[1]["pending_artifacts"] == 2
        if ending == "rst":  # how a killed process's socket can end
            dead.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        dead.close()  # its collector crashed, or returned without pulling
        assert _until(lambda: health()[1]["pending_artifacts"] == 1), \
            "an orphan must not hold the roll; the live run's artifact still must"
        assert store.take(DEAD) == [], "an orphan is discarded: nobody can pull it"
        assert [i["name"] for i in store.take(LIVE)] == ["shot.png"]  # the live pull
        body = health()[1]
        # The roll's need-check: nothing open, nothing a live run could collect.
        assert body["open_sessions"] == 0 and body["pending_artifacts"] == 0
    finally:
        live.close()
        dead.close()


def test_a_hold_outlives_the_request_read_timeout(health, checkout, store, monkeypatch):
    """The 15 s slowloris bound applies to reading requests, not to a hold."""
    monkeypatch.setattr(server.Handler, "timeout", 0.2)
    live, head = _hold(health.port, LIVE)
    try:
        assert head.startswith(b"HTTP/1.0 200"), head
        store.add(LIVE, "shot", b"\x89PNG-fake", "image/png")
        time.sleep(1.0)
        assert health()[1]["pending_artifacts"] == 1
    finally:
        live.close()


def test_a_run_never_held_still_counts(health, checkout, store):
    """No hold is not proof of death (a collector from before this protocol,
    or one that could not reach us): those artifacts count until pulled or
    the TTL sweep."""
    store.add(LIVE, "shot", b"\x89PNG-fake", "image/png")
    assert health()[1]["pending_artifacts"] == 1


@pytest.mark.parametrize("bearer,run_id,status", [
    ("", LIVE, b"401"), ("Bearer wrong", LIVE, b"403"), (BEARER, "nothex", b"404")])
def test_hold_needs_the_bearer_and_a_run_id(health, checkout, store, bearer, run_id, status):
    s, head = _hold(health.port, run_id, bearer)
    s.close()
    assert head.split(b" ", 2)[1] == status, head
