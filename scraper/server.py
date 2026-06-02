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
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

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


def _load_token() -> str:
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        tok = f.read().strip()
    if not tok:
        sys.exit(f"scraper: token file {TOKEN_FILE} is empty")
    return tok


EXPECTED_TOKEN = _load_token()


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
        if not hmac.compare_digest(token, EXPECTED_TOKEN):
            self._json(403, {"status": "error", "error": "bad bearer"})
            return False
        return True

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path != "/render":
            self._json(404, {"status": "error", "error": "not found"})
            return
        if not self._check_auth():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"status": "error", "error": "bad length"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(400, {"status": "error", "error": "bad length"})
            return
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._json(400, {"status": "error", "error": "bad json"})
            return
        if not isinstance(req, dict):
            self._json(400, {"status": "error", "error": "bad json"})
            return
        url = req.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
            self._json(400, {"status": "error", "error": "bad url"})
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self._json(400, {"status": "error", "error": "scheme not allowed"})
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
            # Playwright-level error (timeout, navigation aborted, target
            # closed, etc.). Don't leak details — type name only.
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

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        self._json(404, {"status": "error", "error": "not found"})

    def log_message(self, format, *args):  # noqa: A002 (stdlib API)
        sys.stderr.write(f"[scraper] {format % args}\n")


def main() -> None:
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write(f"[scraper] listening on 0.0.0.0:{PORT}\n")
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
