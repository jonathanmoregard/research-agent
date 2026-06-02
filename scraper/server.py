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
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

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
        # Host must resolve outside the loopback / link-local / IMDS
        # ranges — see _BLOCKED_NETS. Best-effort against DNS rebinding;
        # for airtight enforcement run chromium behind an HTTP proxy.
        try:
            parsed = urlparse(url)
        except ValueError:
            self._json(400, {"status": "error", "error": "bad url"})
            return
        host = parsed.hostname or ""
        if not host or _is_blocked_host(host):
            self._json(400, {"status": "error", "error": "host not allowed"})
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
