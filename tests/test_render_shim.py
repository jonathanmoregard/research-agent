"""Tests for the render-shim MCP tools (render_page, intercept_page).

Stubs `_post_scraper` so the tests don't need a live scraper microvm
running. Exercises input validation + payload shape + formatted output
for both tools.

Use:
    uv run python3 tests/test_render_shim.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Make the shim load without a real token file.
_TOKEN_FILE = REPO_ROOT / "tests" / "_render_shim_token_stub"
_TOKEN_FILE.write_text("test-token\n")
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

from agent.shims import render_shim  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# Each test resets this and stubs render_shim._post_scraper to capture
# what payload reached it.
_captured: dict = {}


def _stub_post_scraper(endpoint_url, payload, timeout_ms):
    _captured["endpoint_url"] = endpoint_url
    _captured["payload"] = payload
    _captured["timeout_ms"] = timeout_ms
    return _captured["return_value"]


def _reset(return_value: dict) -> None:
    _captured.clear()
    _captured["return_value"] = return_value
    render_shim._post_scraper = _stub_post_scraper


# ----- intercept_page validation ---------------------------------------

def test_intercept_missing_url():
    _reset({"status": "ok"})
    try:
        render_shim._tool_intercept_page({})
    except RuntimeError as e:
        _assert("url is required" in str(e), f"wrong error: {e}")
        return
    _assert(False, "missing url did not raise")


def test_intercept_non_string_url():
    _reset({"status": "ok"})
    try:
        render_shim._tool_intercept_page({"url": 42})
    except RuntimeError as e:
        _assert("url is required" in str(e), f"wrong error: {e}")
        return
    _assert(False, "non-string url did not raise")


def test_intercept_actions_not_list():
    _reset({"status": "ok"})
    try:
        render_shim._tool_intercept_page({"url": "https://x", "actions": "click"})
    except RuntimeError as e:
        _assert("actions must be a list" in str(e), f"wrong error: {e}")
        return
    _assert(False, "non-list actions did not raise")


def test_intercept_capture_patterns_not_list():
    _reset({"status": "ok"})
    try:
        render_shim._tool_intercept_page(
            {"url": "https://x", "capture_patterns": "/api/.*"}
        )
    except RuntimeError as e:
        _assert(
            "capture_patterns must be a list" in str(e),
            f"wrong error: {e}",
        )
        return
    _assert(False, "non-list capture_patterns did not raise")


def test_intercept_defaults_applied():
    _reset({
        "status": "ok",
        "requested_url": "https://x.com",
        "final_url": "https://x.com",
        "captured": [],
    })
    out = render_shim._tool_intercept_page({"url": "https://x.com"})
    _assert(_captured["endpoint_url"] == render_shim.INTERCEPT_URL,
            f"wrong endpoint: {_captured['endpoint_url']}")
    p = _captured["payload"]
    _assert(p["url"] == "https://x.com", f"url not forwarded: {p}")
    _assert(p["actions"] == [], f"actions default wrong: {p}")
    _assert(p["capture_patterns"] == [], f"patterns default wrong: {p}")
    _assert(p["timeout_ms"] == 30000, f"timeout default wrong: {p}")
    _assert("Captured: 0 response" in out, f"format wrong: {out!r}")


def test_intercept_formats_capture():
    _reset({
        "status": "ok",
        "requested_url": "https://www.tmdn.org/tmview/",
        "final_url": "https://www.tmdn.org/tmview/",
        "captured": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://www.tmdn.org/tmview/api/search",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"q":"kablong"}',
                    "body_truncated": False,
                },
                "response": {
                    "status": 200,
                    "url": "https://www.tmdn.org/tmview/api/search",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"results":[]}',
                    "body_truncated": False,
                },
            }
        ],
    })
    out = render_shim._tool_intercept_page(
        {
            "url": "https://www.tmdn.org/tmview/",
            "actions": [
                {"type": "fill", "selector": "#q", "text": "kablong"},
                {"type": "click", "selector": "button"},
            ],
            "capture_patterns": ["/tmview/api/.*"],
        }
    )
    _assert("Captured: 1 response" in out, f"count missing: {out!r}")
    _assert("POST https://www.tmdn.org/tmview/api/search" in out,
            f"request line missing: {out!r}")
    _assert('Req-Body: {"q":"kablong"}' in out, f"req body missing: {out!r}")
    _assert("HTTP 200" in out, f"http status missing: {out!r}")
    _assert('{"results":[]}' in out, f"response body missing: {out!r}")


def test_intercept_propagates_scraper_error():
    def _fail(_e, _p, _t):
        raise RuntimeError("scraper HTTP 500: boom")
    render_shim._post_scraper = _fail
    try:
        render_shim._tool_intercept_page({"url": "https://x.com"})
    except RuntimeError as e:
        _assert("scraper HTTP 500" in str(e), f"error not propagated: {e}")
        return
    _assert(False, "scraper failure was swallowed")


# ----- render_page sanity (it now goes through _post_scraper too) ------

def test_render_page_payload_shape():
    _reset({
        "status": "ok",
        "requested_url": "https://x.com",
        "final_url": "https://x.com",
        "http_status": 200,
        "title": "OK",
        "html": "<p>hi</p>",
        "truncated": False,
    })
    out = render_shim._tool_render_page({"url": "https://x.com"})
    _assert(_captured["endpoint_url"] == render_shim.API_URL,
            f"render_page hit wrong endpoint: {_captured['endpoint_url']}")
    p = _captured["payload"]
    _assert(p == {"url": "https://x.com", "timeout_ms": 30000},
            f"render_page payload wrong: {p}")
    _assert("<p>hi</p>" in out, f"render output wrong: {out!r}")


def main() -> int:
    tests = [
        test_intercept_missing_url,
        test_intercept_non_string_url,
        test_intercept_actions_not_list,
        test_intercept_capture_patterns_not_list,
        test_intercept_defaults_applied,
        test_intercept_formats_capture,
        test_intercept_propagates_scraper_error,
        test_render_page_payload_shape,
    ]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
    try:
        _TOKEN_FILE.unlink()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
