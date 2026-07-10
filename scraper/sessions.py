"""Browser session manager + artifact store for the scraper microvm.

Sync-Playwright objects have thread affinity, so a single BrowserWorker
thread owns the Playwright instance and every browser/context/page.
HTTP handler threads never touch Playwright: they submit command dicts
via a queue and block on a per-command Event. Max-2 concurrent sessions
means serializing all browser work through one thread costs nothing —
the research agent is single-threaded anyway.

Artifacts live in memory (<= 10 x 2 MiB per run, 64 MiB global) so the
guest filesystem stays untouched; the host pulls and clears them after
each run.
"""
from __future__ import annotations

import base64
import queue
import re
import threading
import time
import uuid

MAX_SESSIONS = 2
SESSION_IDLE_TTL_S = 300.0
MAX_ACTIONS_PER_CALL = 20
MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_SCREENSHOT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACTS_PER_RUN = 10
MAX_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024
ARTIFACT_TTL_S = 30 * 60.0
DEFAULT_VIEWPORT = {"width": 1280, "height": 720}
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
_RUN_ID_RE = re.compile(r"^[a-f0-9]{32}$")
_SESSION_ACTIONS = {
    "goto", "click", "fill", "press", "hover", "scroll", "drag",
    "wait_for_selector", "wait_ms",
}


def validate_artifact_name(name) -> bool:
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def validate_run_id(run_id) -> bool:
    return isinstance(run_id, str) and bool(_RUN_ID_RE.match(run_id))


def _valid_target(t) -> bool:
    if not isinstance(t, dict):
        return False
    if isinstance(t.get("selector"), str) and t["selector"]:
        return True
    if isinstance(t.get("ref"), str) and re.match(r"^e\d{1,5}$", t["ref"]):
        return True
    return isinstance(t.get("x"), (int, float)) and isinstance(t.get("y"), (int, float))


def validate_actions(actions) -> str | None:
    """None if valid, else error string. Mirrors _validate_intercept_inputs style."""
    if not isinstance(actions, list):
        return "actions must be a list"
    if len(actions) > MAX_ACTIONS_PER_CALL:
        return f"too many actions (max {MAX_ACTIONS_PER_CALL})"
    for i, a in enumerate(actions):
        if not isinstance(a, dict):
            return f"action {i} is not an object"
        t = a.get("type")
        if t not in _SESSION_ACTIONS:
            return f"action {i} has unknown type {t!r}"
        if t == "goto" and not (isinstance(a.get("url"), str) and a["url"]):
            return f"action {i}: goto needs url"
        if t in ("click", "hover") and not _valid_target(a.get("target")):
            return f"action {i}: {t} needs target (selector/ref/x,y)"
        if t == "fill" and (not _valid_target(a.get("target"))
                            or not isinstance(a.get("text"), str)):
            return f"action {i}: fill needs target + text"
        if t == "press" and (not _valid_target(a.get("target"))
                             or not isinstance(a.get("key"), str)):
            return f"action {i}: press needs target + key"
        if t == "scroll" and not isinstance(a.get("dy"), (int, float)):
            return f"action {i}: scroll needs dy"
        if t == "drag":
            if not _valid_target(a.get("from")) or not _valid_target(a.get("to")):
                return f"action {i}: drag needs from + to"
            if "steps" in a and not (isinstance(a["steps"], int) and 1 <= a["steps"] <= 100):
                return f"action {i}: drag steps 1..100"
            if "hold_ms" in a and not (isinstance(a["hold_ms"], int) and 0 <= a["hold_ms"] <= 5000):
                return f"action {i}: drag hold_ms 0..5000"
        if t == "wait_for_selector" and not isinstance(a.get("selector"), str):
            return f"action {i}: wait_for_selector needs selector"
        if t == "wait_ms" and not (isinstance(a.get("ms"), int) and 0 < a["ms"] <= 30000):
            return f"action {i}: wait_ms needs ms 1..30000"
    return None


class ArtifactStore:
    """In-memory per-run screenshot store. Thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}  # run_id -> {"ts": float, "items": [..]}
        self._total = 0

    def add(self, run_id: str, name: str, data: bytes, mime: str) -> str:
        ext = ".png" if mime == "image/png" else ".jpg"
        fname = name + ext
        if len(data) > MAX_ARTIFACT_BYTES:
            raise RuntimeError(f"artifact too large ({len(data)} bytes)")
        with self._lock:
            run = self._runs.setdefault(run_id, {"ts": time.monotonic(), "items": []})
            if len(run["items"]) >= MAX_ARTIFACTS_PER_RUN:
                raise RuntimeError(f"artifact limit reached ({MAX_ARTIFACTS_PER_RUN}/run)")
            if any(i["name"] == fname for i in run["items"]):
                raise RuntimeError(f"artifact name already used: {fname}")
            if self._total + len(data) > MAX_ARTIFACT_TOTAL_BYTES:
                raise RuntimeError("artifact store full")
            run["items"].append({"name": fname, "mime": mime, "data": data})
            run["ts"] = time.monotonic()
            self._total += len(data)
        return fname

    def take(self, run_id: str) -> list[dict]:
        """Return-and-clear. Items carry b64 for JSON transport."""
        with self._lock:
            run = self._runs.pop(run_id, None)
            if run is None:
                return []
            out = []
            for i in run["items"]:
                self._total -= len(i["data"])
                out.append({
                    "name": i["name"], "mime": i["mime"],
                    "data_b64": base64.b64encode(i["data"]).decode("ascii"),
                })
            return out

    def sweep(self) -> None:
        now = time.monotonic()
        with self._lock:
            for rid in [r for r, v in self._runs.items()
                        if now - v["ts"] > ARTIFACT_TTL_S]:
                for i in self._runs[rid]["items"]:
                    self._total -= len(i["data"])
                del self._runs[rid]


class _Session:
    __slots__ = ("browser", "context", "page", "last_used", "snapshot_refs_ok")

    def __init__(self, browser, context, page):
        self.browser, self.context, self.page = browser, context, page
        self.last_used = time.monotonic()
        self.snapshot_refs_ok = True


class BrowserWorker(threading.Thread):
    """Single thread owning all Playwright state. submit() is thread-safe."""

    def __init__(self, browser_factory=None, idle_ttl_s: float = SESSION_IDLE_TTL_S):
        super().__init__(daemon=True, name="browser-worker")
        self._factory = browser_factory
        self._ttl = idle_ttl_s
        self._q: queue.Queue = queue.Queue()
        self._sessions: dict[str, _Session] = {}
        self._pw = None
        self.artifacts = ArtifactStore()

    # ---- public API (any thread) ----
    def submit(self, cmd: dict, timeout_s: float = 120.0) -> dict:
        done = threading.Event()
        slot: dict = {}
        self._q.put((cmd, slot, done))
        if not done.wait(timeout_s):
            raise RuntimeError("browser worker timeout")
        if "error" in slot:
            raise RuntimeError(slot["error"])
        return slot["result"]

    def shutdown(self) -> None:
        self._q.put((None, None, None))
        self.join(timeout=10)

    # ---- worker thread ----
    def run(self) -> None:
        if self._factory is None:
            from playwright.sync_api import sync_playwright
            self._pw = sync_playwright().start()
            pw = self._pw

            def factory():
                return pw.chromium.launch(
                    headless=True, args=["--disable-dev-shm-usage"]
                )
            self._factory = factory
        try:
            while True:
                try:
                    item = self._q.get(timeout=30.0)
                except queue.Empty:
                    self._sweep()
                    self.artifacts.sweep()
                    continue
                cmd, slot, done = item
                if cmd is None:
                    break
                try:
                    slot["result"] = self._dispatch(cmd)
                except Exception as e:  # normalized for the HTTP layer
                    slot["error"] = f"{type(e).__name__}: {e}"
                finally:
                    done.set()
        finally:
            for sid in list(self._sessions):
                self._close(sid)
            if self._pw is not None:
                self._pw.stop()

    def _dispatch(self, cmd: dict) -> dict:
        op = cmd["op"]
        if op == "sweep":
            self._sweep()
            self.artifacts.sweep()
            return {"swept": True}
        if op == "open":
            return self._open(cmd)
        sid = cmd.get("session_id") or ""
        if op in ("act", "screenshot", "save_artifact", "close"):
            s = self._sessions.get(sid)
            if s is None:
                raise RuntimeError(
                    "unknown or expired session — call browse_open again"
                )
            s.last_used = time.monotonic()
            if op == "act":
                return self._act(s, cmd)
            if op == "screenshot":
                return self._observe(s, full_page=bool(cmd.get("full_page")))
            if op == "save_artifact":
                data, mime = self._shoot(s.page, full_page=False,
                                         cap=MAX_ARTIFACT_BYTES, artifact=True)
                fname = self.artifacts.add(cmd["run_id"], cmd["name"], data, mime)
                return {"stored": True, "name": fname}
            if op == "close":
                self._close(sid)
                return {"closed": True}
        raise RuntimeError(f"unknown op {op!r}")

    def _open(self, cmd: dict) -> dict:
        self._sweep()
        if len(self._sessions) >= MAX_SESSIONS:
            raise RuntimeError(
                f"session limit ({MAX_SESSIONS}) reached — browse_close one first"
            )
        browser = self._factory()
        context = browser.new_context(
            user_agent=_UA,
            viewport=cmd.get("viewport") or DEFAULT_VIEWPORT,
            accept_downloads=False,
        )
        page = context.new_page()
        s = _Session(browser, context, page)
        sid = uuid.uuid4().hex[:16]
        self._sessions[sid] = s
        page.goto(cmd["url"], wait_until="domcontentloaded",
                  timeout=int(cmd.get("timeout_ms") or 30000))
        out = self._observe(s)
        out["session_id"] = sid
        return out

    def _act(self, s: _Session, cmd: dict) -> dict:
        for a in cmd.get("actions") or []:
            self._do(s, a, int(cmd.get("timeout_ms") or 30000))
        return self._observe(s)

    def _locator(self, s: _Session, target: dict):
        if target.get("selector"):
            return s.page.locator(target["selector"])
        if target.get("ref"):
            return s.page.locator(f"aria-ref={target['ref']}")
        return None

    def _point(self, s: _Session, target: dict) -> tuple[float, float]:
        if "x" in target and "y" in target:
            return float(target["x"]), float(target["y"])
        box = self._locator(s, target).bounding_box()
        if box is None:
            raise RuntimeError("drag target has no bounding box")
        return box["x"] + box["width"] / 2, box["y"] + box["height"] / 2

    def _do(self, s: _Session, a: dict, timeout: int) -> None:
        t = a["type"]
        page = s.page
        if t == "goto":
            page.goto(a["url"], wait_until="domcontentloaded", timeout=timeout)
        elif t == "click":
            loc = self._locator(s, a["target"])
            if loc is not None:
                loc.click(timeout=timeout)
            else:
                x, y = self._point(s, a["target"])
                page.mouse.move(x, y)
                page.mouse.down(); page.mouse.up()
        elif t == "fill":
            self._locator(s, a["target"]).fill(a["text"], timeout=timeout)
        elif t == "press":
            self._locator(s, a["target"]).press(a["key"], timeout=timeout)
        elif t == "hover":
            self._locator(s, a["target"]).hover(timeout=timeout)
        elif t == "scroll":
            page.mouse.wheel(0, float(a["dy"]))
        elif t == "drag":
            x0, y0 = self._point(s, a["from"])
            x1, y1 = self._point(s, a["to"])
            page.mouse.move(x0, y0)
            page.mouse.down()
            if a.get("hold_ms"):
                page.wait_for_timeout(int(a["hold_ms"]))
            page.mouse.move(x1, y1, steps=int(a.get("steps") or 10))
            page.mouse.up()
        elif t == "wait_for_selector":
            page.wait_for_selector(a["selector"], timeout=timeout)
        elif t == "wait_ms":
            page.wait_for_timeout(int(a["ms"]))
        else:  # pragma: no cover — validate_actions gates this
            raise RuntimeError(f"unknown action {t!r}")

    def _shoot(self, page, full_page: bool, cap: int,
               artifact: bool = False) -> tuple[bytes, str]:
        """Screenshot within `cap` bytes. Artifacts prefer lossless PNG;
        observations go straight to JPEG (smaller, agent context is the
        scarce resource). Falls back to harsher JPEG when over cap."""
        if artifact:
            data = page.screenshot(type="png", full_page=full_page)
            if len(data) <= cap:
                return data, "image/png"
        for quality in (70, 40):
            data = page.screenshot(type="jpeg", quality=quality,
                                   full_page=full_page)
            if len(data) <= cap:
                return data, "image/jpeg"
        raise RuntimeError("screenshot exceeds size cap even at low quality")

    def _observe(self, s: _Session, full_page: bool = False) -> dict:
        data, mime = self._shoot(s.page, full_page, MAX_SCREENSHOT_BYTES)
        snapshot = ""
        try:
            body = s.page.locator("body")
            if s.snapshot_refs_ok:
                try:
                    snapshot = body.aria_snapshot(ref=True)
                except TypeError:
                    # nixpkgs Playwright predates ref support
                    s.snapshot_refs_ok = False
            if not snapshot:
                snapshot = body.aria_snapshot()
        except Exception:
            snapshot = "(aria snapshot unavailable)"
        enc = snapshot.encode("utf-8", errors="replace")
        if len(enc) > MAX_SNAPSHOT_BYTES:
            snapshot = enc[:MAX_SNAPSHOT_BYTES].decode("utf-8", errors="replace") \
                + "\n[snapshot truncated]"
        return {
            "screenshot_b64": base64.b64encode(data).decode("ascii"),
            "screenshot_mime": mime,
            "snapshot": snapshot,
            "final_url": s.page.url,
            "title": s.page.title(),
        }

    def _sweep(self) -> None:
        now = time.monotonic()
        for sid in [k for k, v in self._sessions.items()
                    if now - v.last_used > self._ttl]:
            self._close(sid)

    def _close(self, sid: str) -> None:
        s = self._sessions.pop(sid, None)
        if s is None:
            return
        for closer in (s.context.close, s.browser.close):
            try:
                closer()
            except Exception:
                pass


_worker_lock = threading.Lock()
_worker: BrowserWorker | None = None


def get_worker() -> BrowserWorker:
    """Lazy singleton — first /session/open starts the thread."""
    global _worker
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = BrowserWorker()
            _worker.start()
        return _worker
