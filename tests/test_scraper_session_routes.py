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
#
# Assign, don't setdefault: under a full-suite run the render-shim test
# modules import first (alphabetically) and hard-set SCRAPER_TOKEN_FILE
# to their own stub, whose contents are "test-token". setdefault would
# then be a no-op, scraper/server.py would cache that token at import,
# and every request here would come back 403 "bad bearer" — passing in
# isolation but failing in the suite. Each module owns the env var for
# the module it is about to import, so an explicit set is correct
# regardless of import order.
_TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
_TOKEN_FILE.write_text("stub-token-for-tests\n")
import os
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

import server   # noqa: E402
import sessions  # noqa: E402

BEARER = "Bearer stub-token-for-tests"


class _FakeWorker:
    def __init__(self):
        self.cmds = []
        # Shared singleton, mirroring BrowserWorker's default: the artifact
        # routes read sessions.get_artifact_store(), never the worker.
        self.artifacts = sessions.get_artifact_store()
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


def test_open_bool_timeout_uses_default():
    """timeout_ms: true must not reach the worker as True/1 — clamp to default."""
    _fake.cmds.clear()
    code, body = _post("/session/open", {"url": "https://example.com/", "timeout_ms": True})
    _assert(code == 200, f"expected 200, got {code}: {body}")
    _assert(len(_fake.cmds) == 1, f"no cmd recorded: {_fake.cmds}")
    got = _fake.cmds[0]["timeout_ms"]
    _assert(got == server.DEFAULT_TIMEOUT_MS, f"timeout_ms should be default ({server.DEFAULT_TIMEOUT_MS}), got {got!r}")


def test_open_bool_viewport_is_400():
    """viewport with bool width must be rejected with 400."""
    code, body = _post("/session/open", {"url": "https://example.com/", "viewport": {"width": True, "height": 700}})
    _assert(code == 400, f"expected 400 for bool viewport width, got {code}: {body}")
    _assert("viewport" in body.get("error", ""), f"unexpected error: {body}")


def test_act_oversized_body_is_400():
    """A body larger than MAX_REQUEST_BYTES on act must return 400, not 200."""
    sid = "ab12" * 4
    url = f"http://127.0.0.1:{_srv_port}/session/{sid}/act"
    # 70 KiB body — above the 64 KiB cap
    big_body = b'{"actions":[]}' + b" " * (70 * 1024)
    req = urllib.request.Request(url, data=big_body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", str(len(big_body)))
    req.add_header("Authorization", BEARER)
    try:
        with urllib.request.urlopen(req) as r:
            code, body = r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        code, body = e.code, json.loads(e.read())
    _assert(code == 400, f"expected 400 for oversized act body, got {code}: {body}")


def test_screenshot_empty_body_still_200():
    """screenshot with an empty/no body must still return 200."""
    sid = "ab12" * 4
    url = f"http://127.0.0.1:{_srv_port}/session/{sid}/screenshot"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", "0")
    req.add_header("Authorization", BEARER)
    try:
        with urllib.request.urlopen(req) as r:
            code, body = r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        code, body = e.code, json.loads(e.read())
    _assert(code == 200, f"expected 200 for screenshot with empty body, got {code}: {body}")


def test_act_goto_url_too_long_is_400():
    """goto action with URL > MAX_URL_LEN must return 400."""
    sid = "ab12" * 4
    long_url = "https://example.com/" + "a" * (server.MAX_URL_LEN + 1)
    actions = [{"type": "goto", "url": long_url}]
    code, body = _post(f"/session/{sid}/act", {"actions": actions})
    _assert(code == 400, f"expected 400 for overlong goto url, got {code}: {body}")
    _assert("url too long" in body.get("error", ""), f"unexpected error: {body}")


def test_artifacts_get_without_bearer_is_401():
    """GET /artifacts/{id} without bearer must return 401."""
    run_id = "e" * 32
    code, body = _get(f"/artifacts/{run_id}", auth=None)
    _assert(code == 401, f"expected 401, got {code}: {body}")


def test_artifacts_delete_without_bearer_is_401():
    """DELETE /artifacts/{id} without bearer must return 401."""
    run_id = "f" * 32
    code, body = _delete(f"/artifacts/{run_id}", auth=None)
    _assert(code == 401, f"expected 401, got {code}: {body}")


def test_artifacts_get_does_not_start_worker():
    """GET /artifacts must go through the artifact-store singleton, never
    get_worker() — pulling artifacts must not boot Playwright."""
    run_id = "9" * 32
    sessions.get_artifact_store().add(run_id, "noworker", b"\x89PNG-fake", "image/png")
    worker_calls = []

    def _tripwire():
        worker_calls.append(1)
        return _fake

    orig_sessions_gw, orig_server_gw = sessions.get_worker, server.get_worker
    sessions.get_worker = _tripwire
    server.get_worker = _tripwire
    try:
        code, body = _get(f"/artifacts/{run_id}")
    finally:
        sessions.get_worker = orig_sessions_gw
        server.get_worker = orig_server_gw
    _assert(code == 200, f"expected 200, got {code}: {body}")
    items = body.get("artifacts", [])
    _assert(len(items) == 1, f"expected 1 artifact, got {items}")
    _assert(not worker_calls,
            "GET /artifacts called get_worker (would boot the browser)")
    _assert(sessions._worker is None,
            "a real browser worker was started by the artifact pull")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok: {name}")
    print("ALL PASS")
