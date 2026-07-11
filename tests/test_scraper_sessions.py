"""Tests for scraper/sessions.py — session lifecycle, caps, TTL, artifacts.

Playwright is never imported: BrowserWorker takes an injectable
browser_factory; tests pass _FakeBrowser recording calls.

Use:
    uv run python3 tests/test_scraper_sessions.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scraper") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scraper"))

from sessions import (  # noqa: E402
    ArtifactStore,
    BrowserWorker,
    MAX_ARTIFACTS_PER_RUN,
    MAX_SESSIONS,
    validate_actions,
    validate_artifact_name,
    validate_run_id,
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


class _FakePage:
    def __init__(self):
        self.calls = []
        self.url = "https://x.test/"
    def goto(self, url, **kw): self.calls.append(("goto", url)); self.url = url
    def title(self): return "fake title"
    def screenshot(self, **kw): self.calls.append(("screenshot", kw)); return b"\x89PNG-fake"
    def click(self, sel, **kw): self.calls.append(("click", sel))
    def fill(self, sel, text, **kw): self.calls.append(("fill", sel, text))
    def press(self, sel, key, **kw): self.calls.append(("press", sel, key))
    def hover(self, sel, **kw): self.calls.append(("hover", sel))
    def wait_for_selector(self, sel, **kw): self.calls.append(("wait_for_selector", sel))
    def wait_for_timeout(self, ms): self.calls.append(("wait_ms", ms))
    def locator(self, sel): return _FakeLocator(self, sel)
    class _Mouse:
        def __init__(self, page): self.page = page
        def down(self): self.page.calls.append(("mouse.down",))
        def up(self): self.page.calls.append(("mouse.up",))
        def move(self, x, y, steps=1): self.page.calls.append(("mouse.move", x, y, steps))
        def wheel(self, dx, dy): self.page.calls.append(("wheel", dx, dy))
    @property
    def mouse(self): return _FakePage._Mouse(self)


class _FakeLocator:
    def __init__(self, page, sel): self.page, self.sel = page, sel
    def bounding_box(self): return {"x": 10, "y": 20, "width": 100, "height": 50}
    def aria_snapshot(self, **kw): return "- button \"Go\" [ref=e2]"
    def click(self, **kw): self.page.calls.append(("click", self.sel))
    def fill(self, text, **kw): self.page.calls.append(("fill", self.sel, text))
    def press(self, key, **kw): self.page.calls.append(("press", self.sel, key))
    def hover(self, **kw): self.page.calls.append(("hover", self.sel))


class _FakeContext:
    def new_page(self): return _FakePage()
    def close(self): pass


class _FakeBrowser:
    def __init__(self): self.closed = False
    def new_context(self, **kw): return _FakeContext()
    def close(self): self.closed = True


_made = []
def _fake_factory():
    b = _FakeBrowser(); _made.append(b); return b


def _worker():
    w = BrowserWorker(browser_factory=_fake_factory, idle_ttl_s=9999)
    w.start()
    return w


# ----- validation -----

def test_validate_actions_ok():
    acts = [
        {"type": "goto", "url": "https://a.test/"},
        {"type": "click", "target": {"selector": "#b"}},
        {"type": "fill", "target": {"selector": "#q"}, "text": "hi"},
        {"type": "drag", "from": {"x": 1, "y": 2}, "to": {"x": 9, "y": 9},
         "steps": 5, "hold_ms": 100},
        {"type": "scroll", "dy": 300},
        {"type": "wait_ms", "ms": 50},
    ]
    _assert(validate_actions(acts) is None, f"valid actions rejected: {validate_actions(acts)}")

def test_validate_actions_unknown_type():
    _assert(validate_actions([{"type": "explode"}]) is not None, "unknown type accepted")

def test_validate_actions_too_many():
    _assert(validate_actions([{"type": "wait_ms", "ms": 1}] * 21) is not None,
            "21 actions accepted (cap is 20)")

def test_validate_actions_drag_missing_to():
    _assert(validate_actions([{"type": "drag", "from": {"x": 1, "y": 1}}]) is not None,
            "drag without 'to' accepted")

def test_validate_names():
    _assert(validate_artifact_name("login-page_1"), "good name rejected")
    _assert(not validate_artifact_name("../etc/passwd"), "traversal name accepted")
    _assert(not validate_artifact_name(""), "empty name accepted")
    _assert(not validate_artifact_name("x" * 65), "long name accepted")
    _assert(validate_run_id("a" * 32), "good run_id rejected")
    _assert(not validate_run_id("A" * 32), "uppercase run_id accepted")
    _assert(not validate_run_id("short"), "short run_id accepted")


# ----- session lifecycle -----

def test_open_act_screenshot_close():
    w = _worker()
    try:
        out = w.submit({"op": "open", "url": "https://x.test/"})
        _assert(out["session_id"], "no session_id")
        _assert(out["screenshot_b64"], "no screenshot")
        _assert("ref=e2" in out["snapshot"], "no snapshot")
        sid = out["session_id"]
        out2 = w.submit({"op": "act", "session_id": sid, "actions": [
            {"type": "click", "target": {"selector": "#b"}},
            {"type": "drag", "from": {"x": 1, "y": 1}, "to": {"x": 5, "y": 5}},
        ]})
        _assert(out2["screenshot_b64"], "act returned no screenshot")
        out3 = w.submit({"op": "screenshot", "session_id": sid})
        _assert(out3["screenshot_b64"], "screenshot op failed")
        w.submit({"op": "close", "session_id": sid})
        try:
            w.submit({"op": "act", "session_id": sid, "actions": []})
            _assert(False, "closed session still usable")
        except RuntimeError as e:
            _assert("unknown or expired session" in str(e), f"wrong error: {e}")
    finally:
        w.shutdown()

def test_session_cap():
    w = _worker()
    try:
        sids = [w.submit({"op": "open", "url": "https://x.test/"})["session_id"]
                for _ in range(MAX_SESSIONS)]
        try:
            w.submit({"op": "open", "url": "https://x.test/"})
            _assert(False, "cap not enforced")
        except RuntimeError as e:
            _assert("session limit" in str(e), f"wrong error: {e}")
        for s in sids:
            w.submit({"op": "close", "session_id": s})
    finally:
        w.shutdown()

def test_idle_ttl_sweep():
    w = BrowserWorker(browser_factory=_fake_factory, idle_ttl_s=0.05)
    w.start()
    try:
        sid = w.submit({"op": "open", "url": "https://x.test/"})["session_id"]
        time.sleep(0.15)
        w.submit({"op": "sweep"})
        try:
            w.submit({"op": "act", "session_id": sid, "actions": []})
            _assert(False, "expired session survived sweep")
        except RuntimeError:
            pass
    finally:
        w.shutdown()


# ----- artifact store -----

def test_artifact_caps():
    st = ArtifactStore()
    run = "a" * 32
    for i in range(MAX_ARTIFACTS_PER_RUN):
        st.add(run, f"s{i}", b"png-bytes", "image/png")
    try:
        st.add(run, "one-too-many", b"x", "image/png")
        _assert(False, "artifact count cap not enforced")
    except RuntimeError as e:
        _assert("artifact limit" in str(e), f"wrong error: {e}")
    got = st.take(run)
    _assert(len(got) == MAX_ARTIFACTS_PER_RUN, "take returned wrong count")
    _assert(got[0]["name"].endswith(".png"), "extension not appended")
    _assert(st.take(run) == [], "take did not clear")

def test_artifact_dedup_name():
    st = ArtifactStore()
    run = "b" * 32
    st.add(run, "shot", b"1", "image/png")
    try:
        st.add(run, "shot", b"2", "image/png")
        _assert(False, "duplicate name accepted")
    except RuntimeError:
        pass


# ----- regression: browser leak on failed open -----

class _FailingPage(_FakePage):
    """Page whose goto always raises."""
    def goto(self, url, **kw):
        raise RuntimeError("simulated goto failure")


class _FailingContext:
    def new_page(self): return _FailingPage()
    def close(self): pass


class _FailingBrowser(_FakeBrowser):
    def new_context(self, **kw): return _FailingContext()


_failing_made = []
_ok_made = []

def _mixed_factory():
    """First call returns a failing browser; subsequent calls return normal ones."""
    if not _failing_made:
        b = _FailingBrowser(); _failing_made.append(b); return b
    b = _FakeBrowser(); _ok_made.append(b); return b


def test_browser_leak_on_failed_open():
    """goto failure must not leak the session slot or the browser."""
    w = BrowserWorker(browser_factory=_mixed_factory, idle_ttl_s=9999)
    _failing_made.clear(); _ok_made.clear()
    w.start()
    try:
        # First open must raise
        raised = False
        try:
            w.submit({"op": "open", "url": "https://x.test/"})
        except RuntimeError as e:
            raised = True
            _assert("simulated goto failure" in str(e), f"unexpected error: {e}")
        _assert(raised, "_open did not raise on goto failure")

        # The failing browser must have been closed
        _assert(len(_failing_made) == 1, "failing browser not created")
        _assert(_failing_made[0].closed, "failing browser not closed after error")

        # Both session slots must be free: open MAX_SESSIONS more successfully
        sids = []
        for _ in range(MAX_SESSIONS):
            out = w.submit({"op": "open", "url": "https://x.test/"})
            sids.append(out["session_id"])
        _assert(len(sids) == MAX_SESSIONS, "could not open sessions after failed open")
        for sid in sids:
            w.submit({"op": "close", "session_id": sid})
    finally:
        w.shutdown()


# ----- act budget (review fix: bounded per-call execution) -----

def test_act_budget_exceeded():
    """An exhausted act budget must fail before running the action."""
    w = BrowserWorker(browser_factory=_fake_factory, idle_ttl_s=9999,
                      act_budget_ms=0)
    w.start()
    try:
        sid = w.submit({"op": "open", "url": "https://x.test/"})["session_id"]
        try:
            w.submit({"op": "act", "session_id": sid, "actions": [
                {"type": "click", "target": {"selector": "#b"}},
            ]})
            _assert(False, "act with exhausted budget did not raise")
        except RuntimeError as e:
            _assert("act budget exceeded" in str(e), f"wrong error: {e}")
    finally:
        w.shutdown()


def test_act_timeout_clamped_to_remaining_budget():
    """Per-action timeout passed to _do never exceeds the remaining budget,
    and wait_ms sleeps are clamped to it too."""
    budget_ms = 5000
    w = BrowserWorker(browser_factory=_fake_factory, idle_ttl_s=9999,
                      act_budget_ms=budget_ms)
    calls = []
    orig_do = w._do
    def _spy_do(s, a, timeout):
        calls.append((a["type"], a.get("ms"), timeout))
        orig_do(s, a, timeout)
    w._do = _spy_do
    w.start()
    try:
        sid = w.submit({"op": "open", "url": "https://x.test/"})["session_id"]
        out = w.submit({"op": "act", "session_id": sid, "actions": [
            {"type": "click", "target": {"selector": "#b"}},
            {"type": "wait_ms", "ms": 30000},
        ], "timeout_ms": 30000})
        _assert(out["screenshot_b64"], "act returned no screenshot")
        _assert(len(calls) == 2, f"expected 2 _do calls, got {calls}")
        for typ, _ms, timeout in calls:
            _assert(0 < timeout <= budget_ms,
                    f"{typ}: per-action timeout {timeout} exceeds "
                    f"remaining budget ({budget_ms}ms cap)")
        wait_ms = calls[1][1]
        _assert(wait_ms is not None and wait_ms <= budget_ms,
                f"wait_ms sleep {wait_ms} not clamped to remaining budget")
    finally:
        w.shutdown()


# ----- regression: submit-after-shutdown hangs -----

def test_submit_after_shutdown_raises_fast():
    """submit() after shutdown must raise RuntimeError promptly (< 2 s)."""
    w = BrowserWorker(browser_factory=_fake_factory, idle_ttl_s=9999)
    w.start()
    w.shutdown()
    _assert(not w.is_alive(), "worker still alive after shutdown")
    t0 = time.monotonic()
    raised = False
    try:
        w.submit({"op": "open", "url": "https://x.test/"}, timeout_s=120.0)
    except RuntimeError as e:
        raised = True
        _assert("not running" in str(e), f"unexpected error: {e}")
    elapsed = time.monotonic() - t0
    _assert(raised, "submit after shutdown did not raise")
    _assert(elapsed < 2.0, f"submit after shutdown took {elapsed:.2f}s (expected < 2s)")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok: {name}")
    print("ALL PASS")
