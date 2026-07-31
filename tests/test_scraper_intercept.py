"""Tests for the new /intercept code path in scraper/server.py.

Exercises ONLY the pure validation + helper functions — the actual
Playwright `intercept()` call needs a browser and lives in the scraper
microvm. Stubs out `playwright.sync_api` before import so the rest of the
module loads in a normal venv without the heavy browser dependency.

Use:
    uv run python3 tests/test_scraper_intercept.py
"""
from __future__ import annotations

import sys
import types
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
# Assign rather than setdefault — see the same block in
# test_scraper_session_routes.py: the render-shim modules import earlier
# in a full-suite run and point this var at a stub holding a different
# token, which setdefault would silently keep.
_TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
_TOKEN_FILE.write_text("stub-token-for-tests\n")
import os
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

from server import (  # noqa: E402
    _validate_intercept_inputs,
    _truncate_text,
    MAX_INTERCEPT_ACTIONS,
    MAX_INTERCEPT_PATTERNS,
    MAX_INTERCEPT_BODY_BYTES,
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


# ----- validation -----

def test_valid_minimal():
    _assert(_validate_intercept_inputs("https://x.com", [], [], 30000) is None,
            "minimal valid input rejected")


def test_valid_full():
    actions = [
        {"type": "wait_for_selector", "selector": "#q"},
        {"type": "fill", "selector": "#q", "text": "kablong"},
        {"type": "click", "selector": "button"},
        {"type": "wait_for_response", "url_pattern": "/api/.*search"},
    ]
    patterns = ["/api/search", "tmview/api/"]
    err = _validate_intercept_inputs("https://www.tmdn.org/", actions, patterns, 30000)
    _assert(err is None, f"full valid input rejected: {err}")


def test_bad_url_empty():
    _assert(_validate_intercept_inputs("", [], [], 30000) == "bad url",
            "empty url not caught")


def test_bad_url_scheme():
    err = _validate_intercept_inputs("ftp://x.com", [], [], 30000)
    _assert(err == "scheme not allowed", f"ftp not rejected: {err}")


def test_too_many_actions():
    too_many = [{"type": "click", "selector": "a"}] * (MAX_INTERCEPT_ACTIONS + 1)
    err = _validate_intercept_inputs("https://x.com", too_many, [], 30000)
    _assert("too many actions" in (err or ""), f"action overflow not caught: {err}")


def test_action_not_dict():
    err = _validate_intercept_inputs("https://x.com", ["click"], [], 30000)
    _assert("not an object" in (err or ""), f"non-dict action not caught: {err}")


def test_unknown_action_type():
    err = _validate_intercept_inputs(
        "https://x.com",
        [{"type": "evil", "selector": "a"}],
        [],
        30000,
    )
    _assert("unknown type" in (err or ""), f"evil action not caught: {err}")


def test_too_many_patterns():
    too_many = ["/api/" + str(i) for i in range(MAX_INTERCEPT_PATTERNS + 1)]
    err = _validate_intercept_inputs("https://x.com", [], too_many, 30000)
    _assert("too many capture_patterns" in (err or ""),
            f"pattern overflow not caught: {err}")


def test_pattern_not_string():
    err = _validate_intercept_inputs("https://x.com", [], [42], 30000)
    _assert("not a non-empty string" in (err or ""),
            f"non-string pattern not caught: {err}")


def test_pattern_bad_regex():
    err = _validate_intercept_inputs("https://x.com", [], ["["], 30000)
    _assert("not a valid regex" in (err or ""), f"bad regex not caught: {err}")


def test_bad_timeout():
    _assert("bad timeout_ms" in (_validate_intercept_inputs("https://x.com", [], [], 0) or ""),
            "zero timeout not caught")
    _assert(
        "bad timeout_ms" in (_validate_intercept_inputs("https://x.com", [], [], 9_999_999_999) or ""),
        "absurd timeout not caught",
    )


def test_patterns_not_list():
    err = _validate_intercept_inputs("https://x.com", [], "not-a-list", 30000)
    _assert(err == "capture_patterns must be a list",
            f"non-list patterns not caught: {err}")


def test_actions_not_list():
    err = _validate_intercept_inputs("https://x.com", "not-a-list", [], 30000)
    _assert(err == "actions must be a list",
            f"non-list actions not caught: {err}")


# ----- truncation -----

def test_truncate_short_unchanged():
    out, trunc = _truncate_text("hello", 100)
    _assert(out == "hello" and not trunc, f"short text mutated: ({out!r}, {trunc})")


def test_truncate_long_caps():
    payload = "x" * (MAX_INTERCEPT_BODY_BYTES + 1)
    out, trunc = _truncate_text(payload, MAX_INTERCEPT_BODY_BYTES)
    _assert(len(out.encode("utf-8")) <= MAX_INTERCEPT_BODY_BYTES,
            f"truncation overran cap: {len(out.encode('utf-8'))}")
    _assert(trunc is True, "truncation flag missing")


def test_truncate_multibyte_safe():
    # 4-byte chars right at the boundary — must not crash on partial.
    payload = "🎸" * 200_000  # 4 bytes per char
    out, trunc = _truncate_text(payload, 100)
    _assert(trunc is True, "expected truncation")
    # Round-trip must be valid UTF-8 (errors='replace' guarantees this).
    out.encode("utf-8")


def main() -> int:
    tests = [
        test_valid_minimal,
        test_valid_full,
        test_bad_url_empty,
        test_bad_url_scheme,
        test_too_many_actions,
        test_action_not_dict,
        test_unknown_action_type,
        test_too_many_patterns,
        test_pattern_not_string,
        test_pattern_bad_regex,
        test_bad_timeout,
        test_patterns_not_list,
        test_actions_not_list,
        test_truncate_short_unchanged,
        test_truncate_long_caps,
        test_truncate_multibyte_safe,
    ]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
    # Clean up the token-file stub so we don't leave detritus.
    try:
        _TOKEN_FILE.unlink()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
