"""Regression tests for the scraper's SSRF gate (scraper/netguard.py).

The scraper VM sits behind QEMU SLIRP, where 10.0.2.2 is the HOST's
loopback: before this gate, render_page("http://10.0.2.2:<port>/") returned
the body of whatever listened on the host's 127.0.0.1. These tests pin the
invariant "only public unicast destinations", including the indirect
routes: a hostname that resolves to a private address, a redirect chain
that ends (or passes) there, and subresource requests a page makes.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scraper") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scraper"))

# server.py imports playwright at module level; stub it (same pattern as
# test_scraper_intercept.py) so these tests run without a browser.
_pw_sync = types.ModuleType("playwright.sync_api")


class _StubError(Exception):
    pass


_pw_sync.Error = _StubError
_pw_sync.sync_playwright = lambda: (_ for _ in ()).throw(NotImplementedError())
sys.modules.setdefault("playwright", types.ModuleType("playwright"))
sys.modules.setdefault("playwright.sync_api", _pw_sync)
_TOKEN_FILE = REPO_ROOT / "tests" / "_scraper_token_stub"
_TOKEN_FILE.write_text("stub-token-for-tests\n")
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

import netguard  # noqa: E402
import server  # noqa: E402

PUBLIC = "93.184.216.34"


@pytest.mark.parametrize("host", [
    "10.0.2.2",            # SLIRP host gateway == host loopback
    "10.0.2.3",            # SLIRP DNS
    "10.1.2.3",
    "172.16.0.1", "172.31.255.255",
    "192.168.1.1",
    "100.64.0.1",          # CGNAT / tailnet
    "169.254.169.254",     # IMDS
    "127.0.0.1", "127.1", "0x7f000001", "2130706433",
    "0x0a000202",          # 10.0.2.2, hex form chromium accepts
    "012.0.2.2",           # 10.0.2.2, octal first octet
    "0.0.0.0",
    "224.0.0.1",
    "::1", "[::1]",
    "::ffff:10.0.2.2",     # IPv4-mapped
    "::ffff:127.0.0.1",
    "2002:0a00:0202::1",   # 6to4 wrapping 10.0.2.2
    "fc00::1", "fd12:3456::1", "fe80::1", "fec0::2",
    "",
])
def test_private_literals_blocked(host):
    assert netguard.is_blocked_host(host)


@pytest.mark.parametrize("host", [PUBLIC, "1.1.1.1", "2606:4700:4700::1111"])
def test_public_literals_allowed(host):
    assert not netguard.is_blocked_host(host)


def _fake_dns(monkeypatch, answers):
    def fake(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in answers]
    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake)


def test_hostname_resolving_to_slirp_gateway_blocked(monkeypatch):
    _fake_dns(monkeypatch, ["10.0.2.2"])
    assert netguard.is_blocked_host("innocent.example")


def test_hostname_with_any_private_answer_blocked(monkeypatch):
    _fake_dns(monkeypatch, [PUBLIC, "192.168.0.10"])
    assert netguard.is_blocked_host("mixed.example")


def test_hostname_with_public_answers_allowed(monkeypatch):
    _fake_dns(monkeypatch, [PUBLIC])
    assert not netguard.is_blocked_host("public.example")


def test_unresolvable_hostname_left_to_chromium(monkeypatch):
    def fail(*a, **kw):
        raise socket.gaierror("nx")
    monkeypatch.setattr(netguard.socket, "getaddrinfo", fail)
    assert not netguard.is_blocked_host("nx.example")


@pytest.mark.parametrize("url", [
    "http://10.0.2.2:18777/",
    "https://192.168.0.1/admin",
    "http://[::ffff:10.0.2.2]:8000/",
    "file:///etc/passwd",
    "ftp://example.com/",
    "javascript:alert(1)",
])
def test_url_gate_refuses(url):
    assert netguard.is_blocked_url(url)


def test_http_api_gate_refuses_host_loopback_url():
    # The exact URL shape the live oracle used against the scraper API.
    h = server.Handler.__new__(server.Handler)
    assert h._check_url_host("http://10.0.2.2:18777/") == "host not allowed"
    assert h._check_url_host(f"http://{PUBLIC}/") is None


# --- redirect chains (Playwright does not route redirect hops) -------------

class _Req:
    def __init__(self, url, redirected_from=None):
        self.url, self.redirected_from = url, redirected_from


class _Resp:
    def __init__(self, *chain):
        # chain is first-hop ... final
        req = None
        for u in chain:
            req = _Req(u, req)
        self.request = req


def test_redirect_to_private_detected():
    resp = _Resp(f"http://{PUBLIC}/r", "http://10.0.2.2:18777/")
    assert netguard.blocked_hop(resp, "http://10.0.2.2:18777/") == "http://10.0.2.2:18777/"


def test_redirect_through_private_hop_detected():
    resp = _Resp(f"http://{PUBLIC}/a", "http://127.0.0.1:9091/x", f"http://{PUBLIC}/b")
    assert netguard.blocked_hop(resp, f"http://{PUBLIC}/b") == "http://127.0.0.1:9091/x"


def test_public_redirect_chain_passes():
    resp = _Resp(f"http://{PUBLIC}/a", "https://1.1.1.1/b")
    assert netguard.blocked_hop(resp, "https://1.1.1.1/b") is None
    assert netguard.blocked_hop(None, "about:blank") is None


def test_render_withholds_page_redirected_to_private(monkeypatch):
    """render() end to end on a fake browser: a public URL that 302s to the
    host gateway must raise, not return the gateway's body."""
    final = "http://10.0.2.2:18777/"

    class Page:
        url = final
        def goto(self, url, **kw):
            return _Resp(url, final)
        def wait_for_load_state(self, *a, **kw):
            pass
        def content(self):
            return "CANARY-HOSTLOOP"
        def title(self):
            return ""
        def evaluate(self, *a):
            return "CANARY-HOSTLOOP"

    class Ctx:
        routed = None
        def route(self, pattern, handler):
            Ctx.routed = pattern
        def new_page(self):
            return Page()
        def close(self):
            pass

    class Browser:
        def new_context(self, **kw):
            return Ctx()
        def close(self):
            pass

    class PW:
        chromium = types.SimpleNamespace(launch=lambda **kw: Browser())
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(server, "sync_playwright", lambda: PW())
    with pytest.raises(server.BlockedDestination):
        server.render(f"http://{PUBLIC}/redirect", 5000)
    assert Ctx.routed == "**/*", "request guard must be installed on the context"


# --- per-request guard ------------------------------------------------------

class _Route:
    def __init__(self, url):
        self.request = types.SimpleNamespace(url=url)
        self.outcome = None
    def abort(self, reason=None):
        self.outcome = "abort"
    def continue_(self):
        self.outcome = "continue"


@pytest.fixture
def guard():
    holder = {}
    ctx = types.SimpleNamespace(route=lambda pattern, h: holder.update(h=h, p=pattern))
    netguard.install_request_guard(ctx)
    assert holder["p"] == "**/*"
    return holder["h"]


@pytest.mark.parametrize("url,outcome", [
    ("http://10.0.2.2:8762/api", "abort"),        # page JS -> host service
    ("ws://10.0.2.2:9091/", "abort"),
    ("http://192.168.1.1/", "abort"),
    ("file:///etc/scraper/token", "abort"),
    (f"https://{PUBLIC}/img.png", "continue"),
    ("data:image/png;base64,AAAA", "continue"),
    ("blob:https://x.example/uuid", "continue"),
])
def test_request_guard(guard, url, outcome):
    r = _Route(url)
    guard(r)
    assert r.outcome == outcome


class _NavRequest:
    def __init__(self, url, *, nav=True, main=True, method="GET", frameless=False):
        self.url = url
        self.method = method
        self._nav = nav
        self._frameless = frameless
        self._parent = None if main else object()

    def is_navigation_request(self):
        return self._nav

    @property
    def frame(self):
        if self._frameless:
            raise RuntimeError("service worker request has no frame")
        return types.SimpleNamespace(parent_frame=self._parent)


def _nav_guard(allowed):
    holder = {}
    ctx = types.SimpleNamespace(route=lambda pattern, h: holder.update(h=h))
    netguard.install_request_guard(ctx, nav_allowed=lambda u: u in allowed)
    return holder["h"]


SEEN = f"https://{PUBLIC}/seen"


@pytest.mark.parametrize("request_,outcome", [
    (_NavRequest(SEEN), "continue"),
    (_NavRequest(f"https://{PUBLIC}/?k=leak"), "abort"),          # click/JS nav to unseen URL
    (_NavRequest(SEEN, method="POST"), "abort"),                  # form POST carries typed data
    (_NavRequest(f"https://{PUBLIC}/?k=leak", main=False), "continue"),  # iframe: author's choice
    (_NavRequest(f"https://{PUBLIC}/x.js", nav=False), "continue"),      # subresource
    (_NavRequest(f"https://{PUBLIC}/sw", frameless=True), "continue"),
    (_NavRequest("http://10.0.2.2:8762/"), "abort"),              # SSRF guard still applies
])
def test_navigation_gate(request_, outcome):
    allowed = {SEEN, "http://10.0.2.2:8762/"}
    r = _Route(request_.url)
    r.request = request_
    _nav_guard(allowed)(r)
    assert r.outcome == outcome


def test_no_predicate_keeps_navigation_ungated(guard):
    r = _Route(f"https://{PUBLIC}/?k=anything")
    r.request = _NavRequest(r.request.url)
    guard(r)
    assert r.outcome == "continue"


def test_every_blocked_net_is_actually_rejected():
    # Guard against a typo'd or dead entry: the first address of every
    # listed net is refused.
    for net in netguard.BLOCKED_NETS:
        assert netguard.is_blocked_ip(net.network_address), net
    assert not netguard.is_blocked_ip(ipaddress.ip_address(PUBLIC))


# --- typed text bound -------------------------------------------------------

CANARY = "canary" + "0a1b2c3d" * 4


@pytest.mark.parametrize("texts,ok", [
    (["usb-c kabel"], True),
    (["Pippi Långstrump", "Stockholm"], True),
    ([CANARY], False),
    (["x" * 33], False),
    (["word " * 21], False),                 # >100 chars in one fill
    (["a" * 60, "b" * 30 + " " + "c" * 20], False),  # split across fills
])
def test_typed_text_bound(texts, ok):
    import urlpolicy
    assert (urlpolicy.typed_text_error(texts) is None) is ok


def test_session_actions_refuse_key_shaped_fill():
    import sessions
    fill = {"type": "fill", "target": {"ref": "e1"}, "text": CANARY}
    assert sessions.validate_actions([fill]) is not None
    fill["text"] = "solkräm"
    assert sessions.validate_actions([fill]) is None
    press = {"type": "press", "target": {"ref": "e1"}, "key": "x" * 40}
    assert "too long" in sessions.validate_actions([press])


def test_intercept_actions_refuse_key_shaped_fill():
    err = server._validate_intercept_inputs(
        "https://x.example/",
        [{"type": "fill", "selector": "#q", "text": CANARY}],
        [], 30000,
    )
    assert err is not None and "typed" in err
    ok = server._validate_intercept_inputs(
        "https://x.example/",
        [{"type": "fill", "selector": "#q", "text": "acme"},
         {"type": "press", "selector": "#q", "key": "Enter"}],
        [], 30000,
    )
    assert ok is None
