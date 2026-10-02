"""Action semantics for scraper/server.py `_do_action`, driven by a fake page.

The real Playwright page lives in the scraper microvm. These tests pin the
behaviour that does not depend on a browser — in particular that
`wait_for_response` works from a record of responses the page has already
seen, because Python Playwright has no `page.wait_for_response` (only the
`expect_response` context manager), and a search XHR often lands before the
action list even starts.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scraper") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scraper"))

if "server" not in sys.modules:
    _pw_sync = types.ModuleType("playwright.sync_api")

    class _StubError(Exception):
        pass

    _pw_sync.Error = _StubError

    def _stub_sync_playwright(*a, **kw):  # pragma: no cover
        raise NotImplementedError("test stub")

    _pw_sync.sync_playwright = _stub_sync_playwright
    sys.modules.setdefault("playwright", types.ModuleType("playwright"))
    sys.modules["playwright.sync_api"] = _pw_sync
    _TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
    _TOKEN_FILE.write_text("stub-token-for-tests\n")
    os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

import server  # noqa: E402


class FakePage:
    """Page whose clock only moves through wait_for_timeout.

    `arrivals` maps elapsed-ms → URL that the page "receives" at that time.
    Deliberately has no wait_for_response attribute, like the real
    Python sync API.
    """

    def __init__(self, seen: list[str], arrivals: dict[int, str] | None = None):
        self.seen = seen
        self.arrivals = dict(arrivals or {})
        self.elapsed = 0

    def wait_for_timeout(self, ms: int) -> None:
        self.elapsed += ms
        for at in sorted(list(self.arrivals)):
            if at <= self.elapsed:
                self.seen.append(self.arrivals.pop(at))


def _wait(pattern: str, timeout_ms: int = 1000) -> dict:
    return {"type": "wait_for_response", "url_pattern": pattern, "timeout_ms": timeout_ms}


def test_wait_for_response_already_seen_returns_without_waiting():
    seen = ["https://x.algolia.net/1/indexes/*/queries"]
    page = FakePage(seen)
    server._do_action(page, _wait("algolia.net/1/indexes"), 30000, seen)
    assert page.elapsed == 0


def test_wait_for_response_returns_when_match_arrives_later():
    seen: list[str] = ["https://www.sellpy.se/app.js"]
    page = FakePage(seen, {300: "https://x.algolia.net/1/indexes/*/queries"})
    server._do_action(page, _wait("algolia.net/1/indexes"), 30000, seen)
    assert 300 <= page.elapsed < 1000


def test_wait_for_response_times_out_with_playwright_error():
    seen: list[str] = ["https://www.sellpy.se/app.js"]
    page = FakePage(seen)
    with pytest.raises(server.PWError):
        server._do_action(page, _wait("algolia.net", timeout_ms=500), 30000, seen)
    assert page.elapsed >= 500


def test_validation_rejects_wait_for_response_without_pattern():
    err = server._validate_intercept_inputs(
        "https://x.com", [{"type": "wait_for_response"}], [], 30000
    )
    assert err and "url_pattern" in err


def test_validation_rejects_wait_for_response_bad_regex():
    err = server._validate_intercept_inputs(
        "https://x.com", [{"type": "wait_for_response", "url_pattern": "["}], [], 30000
    )
    assert err and "url_pattern" in err
