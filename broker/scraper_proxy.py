"""Scraper routes: the provenance gate, typed-text and browser-action
budgets, number snapping, session ownership and the run's nav snapshot.

The broker is the only holder of the scraper bearer and the only path from
the research VM to the scraper. Everything a model can push into a browser
passes here first (docs/egress-broker.md §0.1, §3):
  * every model-authored URL (render/intercept/open entry, act goto) is
    checked against the run's ledger, the shop templates and fixed URLs;
  * typed text (fill, printable press keys) is bounded per call and per run;
  * model-chosen numbers are snapped and browser actions are budgeted;
  * outlinks, final URLs and URLs in returned text feed the ledger.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from broker import config
from broker.runs import RouteError, Run
from scraper import urlpolicy

# Reads the scraper's reply; render carries up to 512 KiB HTML + 256 KiB
# text, JSON-escaped, plus links[] (up to 2000 URLs).
MAX_SCRAPER_REPLY_BYTES = 16 * 1024 * 1024
MAX_INTERCEPT_ACTIONS = 32
MAX_ACT_ACTIONS = 20
_SID_CHARS = set("0123456789abcdef")


class Scraper:
    """HTTP client for the scraper API (host loopback hostfwd)."""

    def __init__(self, base: str = config.SCRAPER_BASE,
                 token_file: str = config.SCRAPER_TOKEN_FILE):
        self.base = base
        self.token_file = token_file

    def _token(self) -> str:
        # Re-read per request: the host rotates it on demand.
        try:
            with open(self.token_file, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    def post(self, path: str, payload: dict, timeout_s: float) -> tuple[int, dict]:
        token = self._token()
        if not token:
            raise RouteError(502, "scraper unavailable (no bearer)", "scraper_down")
        req = urllib.request.Request(
            self.base + path, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310 - fixed http://127.0.0.1 base
                status, raw = resp.status, resp.read(MAX_SCRAPER_REPLY_BYTES + 1)
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read(4096)
        except (urllib.error.URLError, OSError, TimeoutError):
            raise RouteError(502, "scraper unavailable", "scraper_down") from None
        if len(raw) > MAX_SCRAPER_REPLY_BYTES:
            raise RouteError(502, "scraper response too large", "scraper_error")
        try:
            body = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            raise RouteError(502, "scraper returned non-json", "scraper_error") from None
        return status, body if isinstance(body, dict) else {}


def _ok_or_raise(status: int, body: dict) -> dict:
    if status == 200 and body.get("status") == "ok":
        return body
    err = str(body.get("error") or "unknown")[:200]
    code = status if status in (400, 403, 404) else 502
    raise RouteError(code, f"scraper HTTP {status}: {err}", "scraper_error")


def _gate(run: Run, url, tool: str) -> str:
    if not isinstance(url, str) or not url:
        raise RouteError(400, "url is required", "bad_request")
    verdict = run.check(url)
    if not verdict.allowed:
        run.refuse(verdict.code or "refused")
        shown = (verdict.url or url)[:200]
        raise RouteError(403, f"{tool} refused by the provenance gate: {verdict.reason}\n"
                              f"URL: {shown}", verdict.code or "refused")
    return url


def _timeout(req: dict, default: int = 30000) -> int:
    v = req.get("timeout_ms", default)
    if v is None:
        v = default
    try:
        return urlpolicy.snap_choice(v, urlpolicy.TIMEOUT_STEPS, "timeout_ms")
    except ValueError:
        raise RouteError(400, "timeout_ms must be a number", "bad_request") from None


def _typed(run: Run, fills: list[str], keys: list[str]) -> int:
    """Per-call typed rule + press grammar; returns the per-run cost."""
    for key in keys:
        err = urlpolicy.press_key_error(key)
        if err:
            run.refuse("press_key")
            raise RouteError(400, err, "press_key")
    err = urlpolicy.typed_text_error(fills)
    if err:
        run.refuse("typed_text")
        raise RouteError(400, err, "typed_text")
    return sum(len(t) for t in fills) + sum(urlpolicy.press_typed_cost(k) for k in keys)


def _harvest(run: Run, out: dict, texts: list[str]) -> None:
    final = out.get("final_url") if isinstance(out.get("final_url"), str) else ""
    urls: list[str] = [final] if final else []
    links = out.get("links")
    if isinstance(links, list):
        urls += [u for u in links[:urlpolicy.MAX_URLS_PER_TEXT] if isinstance(u, str)]
    for text in texts:
        if not isinstance(text, str) or not text:
            continue
        urls += urlpolicy.extract_urls(text)
        if final:
            urls += urlpolicy.relative_targets(urlpolicy.relative_paths(text), final)
    run.harvest(urls)


def _strip(out: dict) -> dict:
    # links[] only feeds the ledger; the model's context does not grow.
    out = dict(out)
    out.pop("links", None)
    return out


def render(scraper: Scraper, run: Run, req: dict) -> dict:
    url = _gate(run, req.get("url"), "render_page")
    timeout_ms = _timeout(req)
    run.spend("render")
    status, out = scraper.post("/render", {"url": url, "timeout_ms": timeout_ms},
                               config.SCRAPER_TIMEOUT_S["render"])
    out = _ok_or_raise(status, out)
    # Never harvested: requested_url (model-authored).
    _harvest(run, out, [out.get("text"), out.get("html")])
    return _strip(out)


def intercept(scraper: Scraper, run: Run, req: dict) -> dict:
    url = _gate(run, req.get("url"), "intercept_page")
    actions = req.get("actions") or []
    if not isinstance(actions, list) or len(actions) > MAX_INTERCEPT_ACTIONS \
            or not all(isinstance(a, dict) for a in actions):
        raise RouteError(400, f"actions must be a list of at most {MAX_INTERCEPT_ACTIONS} "
                              "objects", "bad_request")
    patterns = req.get("capture_patterns") or []
    if not isinstance(patterns, list):
        raise RouteError(400, "capture_patterns must be a list", "bad_request")
    fills = [a.get("text", "") for a in actions if a.get("type") == "fill"]
    if not all(isinstance(t, str) for t in fills):
        raise RouteError(400, "fill text must be a string", "bad_request")
    keys = [a.get("key") for a in actions if a.get("type") == "press"]
    typed = _typed(run, fills, keys)
    try:
        actions = urlpolicy.normalize_intercept_actions(actions)
    except ValueError as e:
        raise RouteError(400, f"bad action number: {e}", "bad_request") from None
    timeout_ms = _timeout(req)
    run.spend("render")
    run.spend_browser(len(actions), typed)
    payload = {"url": url, "actions": actions, "capture_patterns": patterns,
               "timeout_ms": timeout_ms, "run_id": run.run_id,
               "nav_policy": run.nav_policy([url])}
    status, out = scraper.post("/intercept", payload, config.SCRAPER_TIMEOUT_S["intercept"])
    out = _ok_or_raise(status, out)
    texts: list[str] = []
    urls: list[str] = []
    for cap in out.get("captured") or []:
        if not isinstance(cap, dict):
            continue
        for side in ("request", "response"):
            part = cap.get(side) if isinstance(cap.get(side), dict) else {}
            if isinstance(part.get("url"), str):
                urls.append(part["url"])
            texts.append(part.get("body"))
    run.harvest(urls)
    _harvest(run, out, texts)
    return _strip(out)


def _count_targets(actions: list[dict]) -> tuple[int, int]:
    drags = sum(1 for a in actions if a.get("type") == "drag")
    xy = sum(1 for a in actions for k in ("target", "from", "to")
             if urlpolicy.is_xy_target(a.get(k)))
    return drags, xy


def session_open(scraper: Scraper, run: Run, req: dict) -> dict:
    url = _gate(run, req.get("url"), "browse_open")
    try:
        viewport = urlpolicy.snap_viewport(req.get("viewport"))
    except ValueError as e:
        raise RouteError(400, str(e), "bad_request") from None
    timeout_ms = _timeout(req)
    run.spend("browse")
    run.spend_browser(1)
    payload = {"url": url, "viewport": viewport, "timeout_ms": timeout_ms,
               "run_id": run.run_id, "nav_policy": run.nav_policy([url])}
    status, out = scraper.post("/session/open", payload, config.SCRAPER_TIMEOUT_S["open"])
    out = _ok_or_raise(status, out)
    sid = out.get("session_id")
    if isinstance(sid, str) and len(sid) == 16 and set(sid) <= _SID_CHARS:
        with run.lock:
            run.sessions[sid] = viewport
    _harvest(run, out, [out.get("snapshot")])
    return _strip(out)


def _own_session(run: Run, sid: str, owner_of) -> dict:
    with run.lock:
        viewport = run.sessions.get(sid)
    if viewport is not None:
        return viewport
    if owner_of(sid) is not None:
        run.refuse("other_run_session")
        raise RouteError(403, "session belongs to another run", "other_run_session")
    raise RouteError(404, "unknown or expired session — call browse_open again",
                     "unknown_session")


def session_act(scraper: Scraper, run: Run, sid: str, req: dict, owner_of) -> dict:
    viewport = _own_session(run, sid, owner_of)
    actions = req.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > MAX_ACT_ACTIONS \
            or not all(isinstance(a, dict) for a in actions):
        raise RouteError(400, f"actions must be a non-empty list of at most "
                              f"{MAX_ACT_ACTIONS} objects", "bad_request")
    gotos = []
    for a in actions:
        if a.get("type") == "goto":
            gotos.append(_gate(run, a.get("url"), "browse_act goto"))
    fills = [a.get("text") for a in actions if a.get("type") == "fill"]
    if not all(isinstance(t, str) for t in fills):
        raise RouteError(400, "fill text must be a string", "bad_request")
    keys = [a.get("key") for a in actions if a.get("type") == "press"]
    typed = _typed(run, fills, keys)
    try:
        actions = urlpolicy.normalize_session_actions(actions, viewport)
    except ValueError as e:
        raise RouteError(400, f"bad action number: {e}", "bad_request") from None
    drags, xy = _count_targets(actions)
    run.spend("browse")
    run.spend_browser(len(actions), typed, drags, xy)
    payload = {"actions": actions, "run_id": run.run_id,
               "nav_policy": run.nav_policy(gotos)}
    status, out = scraper.post(f"/session/{sid}/act", payload, config.SCRAPER_TIMEOUT_S["act"])
    if status == 502 and "unknown or expired session" in str(out.get("error", "")):
        with run.lock:
            run.sessions.pop(sid, None)
    out = _ok_or_raise(status, out)
    _harvest(run, out, [out.get("snapshot")])
    return _strip(out)


def session_op(scraper: Scraper, run: Run, sid: str, op: str, req: dict, owner_of) -> dict:
    _own_session(run, sid, owner_of)
    payload: dict = {"run_id": run.run_id}  # from the token, never the body
    if op == "screenshot":
        run.spend_browser(1)
        payload["full_page"] = req.get("full_page") is True
    elif op == "save_artifact":
        name = req.get("name")
        if not isinstance(name, str) or not name:
            raise RouteError(400, "name is required", "bad_request")
        run.spend_browser(1)
        payload["name"] = name
    status, out = scraper.post(f"/session/{sid}/{op}", payload, config.SCRAPER_TIMEOUT_S[op])
    if op == "close":
        with run.lock:
            run.sessions.pop(sid, None)
    return _strip(_ok_or_raise(status, out))


def close_all(scraper: Scraper, run: Run) -> None:
    """Run end: close the run's sessions (the scraper's idle TTL is the backstop)."""
    with run.lock:
        sids = list(run.sessions)
        run.sessions.clear()
    for sid in sids:
        try:
            scraper.post(f"/session/{sid}/close", {"run_id": run.run_id},
                         config.SCRAPER_TIMEOUT_S["close"])
        except RouteError:
            pass
