"""Tests for /session/* and /artifacts/* HTTP routes in scraper/server.py.

Stubs playwright.sync_api and sessions.get_worker so the routes are exercised
without a real browser. Drives a real ThreadingHTTPServer on an ephemeral port.

Use:
    uv run python3 tests/test_scraper_session_routes.py
"""
from __future__ import annotations

import json
import sys
import threading
import types
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scraper") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scraper"))

# Stub playwright.sync_api before the module-level import in server.py runs.
_pw_sync = types.ModuleType("playwright.sync_api")
class _StubError(Exception):
    pass
_pw_sync.Error = _StubError
def _stub_sync_playwright(*a, **kw):  # pragma: no cover — never called here
    raise NotImplementedError("test stub")
_pw_sync.sync_playwright = _stub_sync_playwright
sys.modules.setdefault("playwright", types.ModuleType("playwright"))
sys.modules["playwright.sync_api"] = _pw_sync

# Stub the token file before _load_token() runs at import time.
_TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
_TOKEN_FILE.write_text("stub-token-for-tests\n")
import os
os.environ.setdefault("SCRAPER_TOKEN_FILE", str(_TOKEN_FILE))

import server   # noqa: E402
import sessions  # noqa: E402

BEARER = "Bearer stub-token-for-tests"


class _FakeWorker:
    def __init__(self):
        self.cmds = []
        self.artifacts = sessions.ArtifactStore()
        self._raise = False

    def submit(self, cmd, timeout_s=120.0):
        if self._raise:
            raise RuntimeError("worker exploded")
        self.cmds.append(cmd)
        if cmd["op"] == "open":
            return {
                "session_id": "ab12" * 4,
                "screenshot_b64": "aGk=",
                "screenshot_mime": "image/jpeg",
                "snapshot": "- s",
                "final_url": cmd["url"],
                "title": "t",
            }
        return {"ok": True}


_fake = _FakeWorker()
sessions.get_worker = lambda: _fake   # route layer must call through this
server.get_worker = lambda: _fake     # (server imports the symbol)

# Start a throwaway server on an ephemeral port.
_srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
_srv_port = _srv.server_address[1]
threading.Thread(target=_srv.serve_forever, daemon=True).start()


def _post(path: str, body: dict | None, *, auth: str | None = BEARER) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{_srv_port}{path}"
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", str(len(data)))
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(path: str, *, auth: str | None = BEARER) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{_srv_port}{path}"
    req = urllib.request.Request(url, method="GET")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _delete(path: str, *, auth: str | None = BEARER) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{_srv_port}{path}"
    req = urllib.request.Request(url, method="DELETE")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# ---- tests ----

def test_open_requires_auth():
    code, body = _post("/session/open", {"url": "https://example.com/"}, auth=None)
    _assert(code == 401, f"expected 401, got {code}: {body}")
    _assert(body["status"] == "error", "no error status")


def test_open_blocked_host():
    code, body = _post("/session/open", {"url": "http://127.0.0.1/"})
    _assert(code == 400, f"expected 400, got {code}: {body}")
    _assert("host not allowed" in body.get("error", ""), f"unexpected error: {body}")


def test_open_ok():
    _fake.cmds.clear()
    code, body = _post("/session/open", {"url": "https://example.com/"})
    _assert(code == 200, f"expected 200, got {code}: {body}")
    _assert(body.get("status") == "ok", f"bad status: {body}")
    _assert("session_id" in body, f"no session_id: {body}")
    _assert(len(_fake.cmds) == 1, f"wrong cmd count: {_fake.cmds}")
    _assert(_fake.cmds[0]["op"] == "open", f"wrong op: {_fake.cmds[0]}")


def test_open_bad_viewport():
    code, body = _post("/session/open", {"url": "https://example.com/", "viewport": {"width": 100, "height": 100}})
    _assert(code == 400, f"expected 400 for bad viewport, got {code}: {body}")
    _assert("viewport" in body.get("error", ""), f"unexpected error: {body}")


def test_open_good_viewport():
    _fake.cmds.clear()
    code, body = _post("/session/open", {"url": "https://example.com/", "viewport": {"width": 1280, "height": 720}})
    _assert(code == 200, f"expected 200 with valid viewport, got {code}: {body}")


def test_act_validates_actions():
    sid = "ab12" * 4
    code, body = _post(f"/session/{sid}/act", {"actions": [{"type": "explode"}]})
    _assert(code == 400, f"expected 400, got {code}: {body}")
    _assert("unknown type" in body.get("error", ""), f"unexpected error: {body}")


def test_act_goto_blocked_host():
    sid = "ab12" * 4
    actions = [{"type": "goto", "url": "http://127.0.0.1/"}]
    code, body = _post(f"/session/{sid}/act", {"actions": actions})
    _assert(code == 400, f"expected 400, got {code}: {body}")
    _assert("host not allowed" in body.get("error", ""), f"unexpected error: {body}")


def test_act_bad_session_path():
    # Non-hex session id should 404
    code, body = _post("/session/NOTHEXVALUE!!/act", {"actions": []})
    _assert(code == 404, f"expected 404 for bad path, got {code}: {body}")


def test_act_ok():
    _fake.cmds.clear()
    sid = "ab12" * 4
    actions = [{"type": "click", "target": {"selector": "#btn"}}]
    code, body = _post(f"/session/{sid}/act", {"actions": actions})
    _assert(code == 200, f"expected 200, got {code}: {body}")
    _assert(_fake.cmds[-1]["op"] == "act", f"wrong op: {_fake.cmds[-1]}")


def test_save_artifact_bad_name():
    sid = "ab12" * 4
    run_id = "a" * 32
    code, body = _post(f"/session/{sid}/save_artifact", {"name": "../etc/passwd", "run_id": run_id})
    _assert(code == 400, f"expected 400, got {code}: {body}")
    _assert("bad artifact name" in body.get("error", ""), f"unexpected error: {body}")


def test_save_artifact_bad_run_id():
    sid = "ab12" * 4
    code, body = _post(f"/session/{sid}/save_artifact", {"name": "screenshot1", "run_id": "short"})
    _assert(code == 400, f"expected 400, got {code}: {body}")
    _assert("bad run_id" in body.get("error", ""), f"unexpected error: {body}")


def test_artifacts_get_and_clear():
    run_id = "c" * 32
    _fake.artifacts.add(run_id, "shot1", b"\x89PNG-fake", "image/png")
    code, body = _get(f"/artifacts/{run_id}")
    _assert(code == 200, f"expected 200, got {code}: {body}")
    _assert(body["status"] == "ok", f"bad status: {body}")
    items = body.get("artifacts", [])
    _assert(len(items) == 1, f"expected 1 artifact, got {len(items)}: {items}")
    _assert(items[0]["name"] == "shot1.png", f"wrong name: {items[0]}")
    # Second GET should return empty (take-and-clear)
    code2, body2 = _get(f"/artifacts/{run_id}")
    _assert(code2 == 200, f"second GET expected 200, got {code2}")
    _assert(body2["artifacts"] == [], f"second GET not cleared: {body2}")


def test_artifacts_delete():
    run_id = "d" * 32
    _fake.artifacts.add(run_id, "shot2", b"\x89PNG-fake", "image/png")
    code, body = _delete(f"/artifacts/{run_id}")
    _assert(code == 200, f"expected 200, got {code}: {body}")
    _assert(body.get("cleared") is True, f"no cleared=true: {body}")
    # Confirm cleared
    code2, body2 = _get(f"/artifacts/{run_id}")
    _assert(body2["artifacts"] == [], f"not cleared after DELETE: {body2}")


def test_worker_error_is_502():
    _fake._raise = True
    try:
        code, body = _post("/session/open", {"url": "https://example.com/"})
        _assert(code == 502, f"expected 502, got {code}: {body}")
        _assert(body["status"] == "error", f"bad status: {body}")
        _assert("worker exploded" in body.get("error", ""), f"wrong error: {body}")
    finally:
        _fake._raise = False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok: {name}")
    print("ALL PASS")
