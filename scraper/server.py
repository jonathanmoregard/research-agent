#!/usr/bin/env python3
"""Scraper HTTP API — runs inside the scraper microvm.

POST /render
    body:  {"url": "https://...", "timeout_ms": 30000}
    auth:  Authorization: Bearer <token-from-/etc/scraper/token>
    reply: {"status": "ok", "requested_url", "final_url", "http_status",
            "title", "html"}
          or {"status": "error", "error": "<short reason>"}

GET /health → {"status": "ok"}

Per-request isolation: each call launches a fresh chromium process via
Playwright and tears it down. No shared browser, no shared context. A
JS exploit in one render cannot reach the next.

Defense-in-depth — the VM itself is the hard boundary; chromium's own
sandbox is the second layer. The HTTP API surface here just gates
authorization and basic input shape.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

from sessions import (
    get_worker,
    validate_actions,
    validate_artifact_name,
    validate_run_id,
)

PORT = int(os.environ.get("SCRAPER_PORT", "8000"))
TOKEN_FILE = os.environ.get("SCRAPER_TOKEN_FILE", "/etc/scraper/token")

MAX_URL_LEN = 4096
MAX_REQUEST_BYTES = 64 * 1024
MAX_TIMEOUT_MS = 60_000
DEFAULT_TIMEOUT_MS = 30_000
# Cap on returned HTML so a malicious target site can't balloon caller
# context. Truncation marker appended when hit; the agent gets a clear
# signal rather than silent loss.
MAX_HTML_BYTES = 512 * 1024


def _clamp_timeout(v) -> int:
    if not isinstance(v, int) or v <= 0 or v > MAX_TIMEOUT_MS:
        return DEFAULT_TIMEOUT_MS
    return v


_SESSION_PATH = re.compile(
    r"^/session/([a-f0-9]{16})/(act|screenshot|save_artifact|close)$"
)
_ARTIFACTS_PATH = re.compile(r"^/artifacts/([a-f0-9]{32})$")


def _load_token() -> str:
    """Read the bearer token from disk.

    Re-read on every request rather than cached at import: the host's
    scraper-bearer-init.service rotates the token on demand
    (`systemctl restart scraper-bearer-init`), and the agent-side
    render_shim already re-reads per call (process is spawned per MCP
    invocation). Caching here would desync the two sides on rotation,
    silently 403'ing every call until the scraper-http process restarts.
    Cost: ~microsecond tmpfs read per request — negligible vs the
    chromium spawn that follows.
    """
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        tok = f.read().strip()
    if not tok:
        raise RuntimeError(f"scraper: token file {TOKEN_FILE} is empty")
    return tok


# Validate at startup that the token file exists + is non-empty —
# fail-fast at service boot rather than 500ing the first real request.
_load_token()


# SSRF blocklist. Reject URLs whose hostname resolves into one of these
# ranges. Defense-in-depth — the prod host has no cloud metadata service
# and the scraper VM's SLIRP NAT already isolates it from the host LAN,
# but if the VM is ever migrated to a cloud or someone wires bridged
# networking, IMDS / link-local exfil becomes possible. Cheap to block
# at the URL gate.
_BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",       # loopback (including 127.0.0.1 — self-recursion)
        "169.254.0.0/16",    # link-local (AWS/GCP/Azure IMDS, IPv4)
        "::1/128",           # loopback v6
        "fe80::/10",         # link-local v6
        "fc00::/7",          # unique-local v6 (includes IMDSv6)
    )
]


def _is_blocked_host(host: str) -> bool:
    """True if host (literal or after DNS) resolves into a blocked range.

    Handles literal IP inputs in all the historic forms inet_aton accepts
    (dot-quad, integer, hex, octal, mixed) before falling back to DNS, so
    `http://2130706433/` (= 127.0.0.1) and `http://0x7f000001/` cannot
    bypass the gate via a form that glibc's getaddrinfo refuses to
    resolve (EAI_NONAME). Chromium's own URL parser accepts all of these,
    so we MUST normalize before checking.

    For genuine hostnames: resolves every A/AAAA so DNS rebinding can't
    slip a legitimate-looking hostname through that later swaps to
    169.254.x. Chromium does its own second lookup — we cannot bind it
    to our pre-resolved IP — so this remains best-effort. For airtight
    enforcement, run chromium behind an outbound HTTP proxy enforcing
    the same blocklist (follow-up).
    """
    # Literal IPv4 in any historic form. inet_aton accepts:
    #   "127.0.0.1", "127.1", "0x7f000001", "017700000001", "2130706433"
    try:
        ipv4 = ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        ipv4 = None
    if ipv4 is not None:
        return any(ipv4 in net for net in _BLOCKED_NETS if net.version == 4)

    # Literal IPv6. Strip zone-id (`fe80::1%eth0`) before inet_pton.
    try:
        ipv6 = ipaddress.IPv6Address(
            socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
        )
    except OSError:
        ipv6 = None
    if ipv6 is not None:
        return any(ipv6 in net for net in _BLOCKED_NETS if net.version == 6)

    # Hostname — resolve and check every answer.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Unresolvable. Let chromium fail with NXDOMAIN downstream.
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        if any(ip in net for net in _BLOCKED_NETS):
            return True
    return False


# --- intercept / form-driving config -----------------------------------------
#
# Defaults for the /intercept endpoint. Bound the size of any one captured
# response so a hostile target page can't balloon the agent's context with a
# multi-megabyte JSON payload; bound the number of actions per call so a
# poorly-written script can't pin a chromium process indefinitely; bound the
# capture-pattern list so we don't blow runtime walking a runaway regex set.
MAX_INTERCEPT_BODY_BYTES = 256 * 1024
MAX_INTERCEPT_CAPTURED = 16
MAX_INTERCEPT_ACTIONS = 32
MAX_INTERCEPT_PATTERNS = 8
_VALID_ACTION_TYPES = {
    "wait_for_selector",
    "wait_for_load_state",
    "wait_for_timeout_ms",
    "wait_for_response",
    "fill",
    "click",
    "press",
}


def _validate_intercept_inputs(
    url: str,
    actions: list,
    capture_patterns: list,
    timeout_ms: int,
) -> str | None:
    """Return None if valid, else an error string (no exception leaks)."""
    if not isinstance(url, str) or not url:
        return "bad url"
    if len(url) > MAX_URL_LEN:
        return "url too long"
    if not (url.startswith("http://") or url.startswith("https://")):
        return "scheme not allowed"
    if not isinstance(actions, list):
        return "actions must be a list"
    if len(actions) > MAX_INTERCEPT_ACTIONS:
        return f"too many actions (max {MAX_INTERCEPT_ACTIONS})"
    for i, action in enumerate(actions):
        if not isinstance(action, dict):
            return f"action {i} is not an object"
        t = action.get("type")
        if t not in _VALID_ACTION_TYPES:
            return f"action {i} has unknown type {t!r}"
    if not isinstance(capture_patterns, list):
        return "capture_patterns must be a list"
    if len(capture_patterns) > MAX_INTERCEPT_PATTERNS:
        return f"too many capture_patterns (max {MAX_INTERCEPT_PATTERNS})"
    for i, p in enumerate(capture_patterns):
        if not isinstance(p, str) or not p:
            return f"capture_pattern {i} not a non-empty string"
        try:
            re.compile(p)
        except re.error:
            return f"capture_pattern {i} not a valid regex"
    if (
        not isinstance(timeout_ms, int)
        or timeout_ms <= 0
        or timeout_ms > MAX_TIMEOUT_MS
    ):
        return f"bad timeout_ms (1..{MAX_TIMEOUT_MS})"
    return None


def _do_action(page, action: dict, default_timeout_ms: int) -> None:
    """Apply one action. Raises Playwright errors on failure — the caller
    catches them and returns a structured error to the API client.
    """
    t = action["type"]
    timeout = int(action.get("timeout_ms") or default_timeout_ms)
    if t == "wait_for_selector":
        page.wait_for_selector(action["selector"], timeout=timeout)
    elif t == "wait_for_load_state":
        page.wait_for_load_state(action.get("state", "domcontentloaded"), timeout=timeout)
    elif t == "wait_for_timeout_ms":
        page.wait_for_timeout(int(action.get("ms", 1000)))
    elif t == "wait_for_response":
        pattern = re.compile(action["url_pattern"])
        page.wait_for_response(
            lambda resp: bool(pattern.search(resp.url)),
            timeout=timeout,
        )
    elif t == "fill":
        page.fill(action["selector"], action.get("text", ""))
    elif t == "click":
        page.click(action["selector"])
    elif t == "press":
        page.press(action["selector"], action["key"])
    else:  # pragma: no cover — _validate_intercept_inputs gates this
        raise ValueError(f"unknown action: {t}")


def _truncate_text(body: str, cap: int) -> tuple[str, bool]:
    enc = body.encode("utf-8", errors="replace")
    if len(enc) <= cap:
        return body, False
    return enc[:cap].decode("utf-8", errors="replace"), True


def intercept(
    url: str,
    actions: list,
    capture_patterns: list,
    timeout_ms: int,
) -> dict:
    """Drive a SPA form and capture matching XHR responses.

    Loads `url`, registers a `response` listener that records every XHR whose
    URL matches any of the `capture_patterns` regexes, runs each action in
    `actions` in order, then returns the captured (request, response) pairs.

    Bodies are returned as text (errors='replace' on non-UTF-8 bytes) and
    capped at MAX_INTERCEPT_BODY_BYTES per response. The number of captured
    pairs is capped at MAX_INTERCEPT_CAPTURED.
    """
    captured: list[dict] = []
    compiled = [re.compile(p) for p in capture_patterns]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--disable-dev-shm-usage"],
        )
        try:
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
                accept_downloads=False,
            )
            page = ctx.new_page()

            def on_response(response):
                if len(captured) >= MAX_INTERCEPT_CAPTURED:
                    return
                if not any(p.search(response.url) for p in compiled):
                    return
                try:
                    body = response.text()
                except Exception:
                    # Binary or otherwise non-text; keep the metadata anyway.
                    body = ""
                body_out, body_truncated = _truncate_text(
                    body, MAX_INTERCEPT_BODY_BYTES
                )
                try:
                    req_post = response.request.post_data or ""
                except Exception:
                    req_post = ""
                req_post_out, req_post_truncated = _truncate_text(
                    req_post, MAX_INTERCEPT_BODY_BYTES
                )
                captured.append({
                    "request": {
                        "method": response.request.method,
                        "url": response.request.url,
                        "headers": dict(response.request.headers),
                        "body": req_post_out,
                        "body_truncated": req_post_truncated,
                    },
                    "response": {
                        "status": response.status,
                        "url": response.url,
                        "headers": dict(response.headers),
                        "body": body_out,
                        "body_truncated": body_truncated,
                    },
                })

            page.on("response", on_response)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                for action in actions:
                    _do_action(page, action, timeout_ms)
                return {
                    "status": "ok",
                    "requested_url": url,
                    "final_url": page.url,
                    "captured": captured,
                }
            finally:
                ctx.close()
        finally:
            browser.close()


def render(url: str, timeout_ms: int) -> dict:
    """Launch chromium, navigate, snapshot post-JS HTML, tear down."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            # Defaults from playwright that we keep:
            #   - chrome's own sandbox stays on (we are not in docker)
            #   - GPU off (no display)
            # Bound the navigation budget so a stuck page can't pin a
            # chromium process forever.
            args=["--disable-dev-shm-usage"],
        )
        try:
            ctx = browser.new_context(
                # Realistic UA so server-side bot detection (Qasa etc.)
                # serves the same HTML a human browser would. We are
                # not pretending to be human in any abusive sense —
                # just asking for the page the human user wanted.
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
                # Don't accept any cookies / persist any state — the
                # context is torn down at the end anyway, but explicit.
                accept_downloads=False,
            )
            page = ctx.new_page()
            try:
                resp = page.goto(
                    url, wait_until="networkidle", timeout=timeout_ms
                )
                html = page.content()
                title = page.title()
                final_url = page.url
                status = resp.status if resp else 0
                truncated = False
                encoded = html.encode("utf-8", errors="replace")
                if len(encoded) > MAX_HTML_BYTES:
                    html = encoded[:MAX_HTML_BYTES].decode(
                        "utf-8", errors="replace"
                    )
                    truncated = True
                return {
                    "status": "ok",
                    "requested_url": url,
                    "final_url": final_url,
                    "http_status": status,
                    "title": title,
                    "html": html,
                    "truncated": truncated,
                }
            finally:
                ctx.close()
        finally:
            browser.close()


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._json(401, {"status": "error", "error": "missing bearer"})
            return False
        token = auth[len("Bearer ") :].strip()
        try:
            expected = _load_token()
        except (OSError, RuntimeError):
            self._json(503, {"status": "error", "error": "token unavailable"})
            return False
        if not hmac.compare_digest(token, expected):
            self._json(403, {"status": "error", "error": "bad bearer"})
            return False
        return True

    def _read_body(self) -> tuple[int, dict | None, str | None]:
        """Returns (length, parsed_dict, error_string). Either parsed is set,
        or error is set. Empties everything else.
        """
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return 0, None, "bad length"
        if length <= 0 or length > MAX_REQUEST_BYTES:
            return length, None, "bad length"
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            return length, None, "bad json"
        if not isinstance(req, dict):
            return length, None, "bad json"
        return length, req, None

    def _check_url_host(self, url: str) -> str | None:
        """Returns error string or None if the URL host is acceptable."""
        if not (url.startswith("http://") or url.startswith("https://")):
            return "scheme not allowed"
        try:
            parsed = urlparse(url)
        except ValueError:
            return "bad url"
        host = parsed.hostname or ""
        if not host or _is_blocked_host(host):
            return "host not allowed"
        return None

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path == "/render":
            self._do_render()
            return
        if self.path == "/intercept":
            self._do_intercept()
            return
        if self.path == "/session/open":
            self._do_session_open()
            return
        m = _SESSION_PATH.match(self.path)
        if m:
            self._do_session_op(m.group(1), m.group(2))
            return
        self._json(404, {"status": "error", "error": "not found"})

    def _submit(self, cmd: dict) -> None:
        """Submit to the browser worker; normalize errors like /render does."""
        try:
            out = get_worker().submit(cmd)
        except RuntimeError as e:
            self._json(502, {"status": "error", "error": str(e)[:300]})
            return
        out["status"] = "ok"
        self._json(200, out)

    def _do_session_open(self) -> None:
        if not self._check_auth():
            return
        _length, req, err = self._read_body()
        if err is not None or req is None:
            self._json(400, {"status": "error", "error": err or "bad json"})
            return
        url = req.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
            self._json(400, {"status": "error", "error": "bad url"})
            return
        host_err = self._check_url_host(url)
        if host_err is not None:
            self._json(400, {"status": "error", "error": host_err})
            return
        viewport = req.get("viewport")
        if viewport is not None and not (
            isinstance(viewport, dict)
            and isinstance(viewport.get("width"), int)
            and isinstance(viewport.get("height"), int)
            and 320 <= viewport["width"] <= 1920
            and 240 <= viewport["height"] <= 1080
        ):
            self._json(400, {"status": "error", "error": "bad viewport"})
            return
        self._submit({"op": "open", "url": url, "viewport": viewport,
                      "timeout_ms": _clamp_timeout(req.get("timeout_ms"))})

    def _do_session_op(self, sid: str, op: str) -> None:
        if not self._check_auth():
            return
        _length, req, err = self._read_body()
        if err is not None or req is None:
            # close/screenshot may come with an empty body; tolerate it
            req = {}
        if op == "act":
            actions = req.get("actions") or []
            verr = validate_actions(actions)
            if verr is not None:
                self._json(400, {"status": "error", "error": verr})
                return
            # URL gate on every goto — the ONLY navigation entry points are
            # /session/open and goto actions, both checked here at the HTTP
            # layer (spec parity with /render).
            for a in actions:
                if a["type"] == "goto":
                    host_err = self._check_url_host(a["url"])
                    if host_err is not None:
                        self._json(400, {"status": "error", "error": host_err})
                        return
            self._submit({"op": "act", "session_id": sid, "actions": actions,
                          "timeout_ms": _clamp_timeout(req.get("timeout_ms"))})
            return
        if op == "screenshot":
            self._submit({"op": "screenshot", "session_id": sid,
                          "full_page": bool(req.get("full_page"))})
            return
        if op == "save_artifact":
            name = req.get("name")
            run_id = req.get("run_id")
            if not validate_artifact_name(name):
                self._json(400, {"status": "error", "error": "bad artifact name"})
                return
            if not validate_run_id(run_id):
                self._json(400, {"status": "error", "error": "bad run_id"})
                return
            self._submit({"op": "save_artifact", "session_id": sid,
                          "name": name, "run_id": run_id})
            return
        if op == "close":
            self._submit({"op": "close", "session_id": sid})
            return
        self._json(404, {"status": "error", "error": "not found"})

    def _do_render(self) -> None:
        if not self._check_auth():
            return
        _length, req, err = self._read_body()
        if err is not None or req is None:
            self._json(400, {"status": "error", "error": err or "bad json"})
            return
        url = req.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
            self._json(400, {"status": "error", "error": "bad url"})
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self._json(400, {"status": "error", "error": "scheme not allowed"})
            return
        # Host must resolve outside the loopback / link-local / IMDS
        # ranges — see _BLOCKED_NETS. Best-effort against DNS rebinding;
        # for airtight enforcement run chromium behind an HTTP proxy.
        host_err = self._check_url_host(url)
        if host_err is not None:
            self._json(400, {"status": "error", "error": host_err})
            return
        timeout_ms = req.get("timeout_ms", DEFAULT_TIMEOUT_MS)
        if (
            not isinstance(timeout_ms, int)
            or timeout_ms <= 0
            or timeout_ms > MAX_TIMEOUT_MS
        ):
            timeout_ms = DEFAULT_TIMEOUT_MS
        try:
            out = render(url, timeout_ms)
        except PWError as e:
            self._json(
                502,
                {"status": "error", "error": f"render failed: {type(e).__name__}"},
            )
            return
        except Exception as e:  # pragma: no cover — fail-loud catchall
            self._json(
                500,
                {"status": "error", "error": f"internal: {type(e).__name__}"},
            )
            return
        self._json(200, out)

    def _do_intercept(self) -> None:
        if not self._check_auth():
            return
        _length, req, err = self._read_body()
        if err is not None or req is None:
            self._json(400, {"status": "error", "error": err or "bad json"})
            return
        url = req.get("url") or ""
        actions = req.get("actions") or []
        capture_patterns = req.get("capture_patterns") or []
        timeout_ms = req.get("timeout_ms", DEFAULT_TIMEOUT_MS)
        if (
            not isinstance(timeout_ms, int)
            or timeout_ms <= 0
            or timeout_ms > MAX_TIMEOUT_MS
        ):
            timeout_ms = DEFAULT_TIMEOUT_MS
        validation_err = _validate_intercept_inputs(
            url, actions, capture_patterns, timeout_ms
        )
        if validation_err is not None:
            self._json(400, {"status": "error", "error": validation_err})
            return
        host_err = self._check_url_host(url)
        if host_err is not None:
            self._json(400, {"status": "error", "error": host_err})
            return
        try:
            out = intercept(url, actions, capture_patterns, timeout_ms)
        except PWError as e:
            self._json(
                502,
                {"status": "error",
                 "error": f"intercept failed: {type(e).__name__}"},
            )
            return
        except Exception as e:  # pragma: no cover — fail-loud catchall
            self._json(
                500,
                {"status": "error", "error": f"internal: {type(e).__name__}"},
            )
            return
        self._json(200, out)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        m = _ARTIFACTS_PATH.match(self.path)
        if m:
            if not self._check_auth():
                return
            items = get_worker().artifacts.take(m.group(1))
            self._json(200, {"status": "ok", "artifacts": items})
            return
        self._json(404, {"status": "error", "error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        m = _ARTIFACTS_PATH.match(self.path)
        if m:
            if not self._check_auth():
                return
            get_worker().artifacts.take(m.group(1))
            self._json(200, {"status": "ok", "cleared": True})
            return
        self._json(404, {"status": "error", "error": "not found"})

    def log_message(self, format, *args):  # noqa: A002 (stdlib API)
        sys.stderr.write(f"[scraper] {format % args}\n")


# Per-connection socket inactivity timeout. Bounds slowloris-style
# attackers that open the socket then trickle bytes — without this,
# BaseHTTPRequestHandler has no read deadline and a handful of slow
# clients can tie up every server thread indefinitely. 15 s is plenty
# of slack for the headers + ~64 KiB JSON body the API accepts.
Handler.timeout = 15


def main() -> None:
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write(f"[scraper] listening on 0.0.0.0:{PORT}\n")
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
