"""Suite-wide network guard (docs/egress-broker.md §8.1).

Standing directive (tasks/session-constraints.md, 2026-09-06/07): no test,
locally or in CI, may open a real network connection; HTTP clients are
exercised only through in-process fakes and loopback stubs. Installed by
tests/conftest.py at import, before any test module loads, so it covers
everything the pytest process itself does:

  * Python sockets: `socket.socket.connect` / `connect_ex` / `sendto` to a
    non-loopback AF_INET/AF_INET6 address, and name resolution of anything
    but loopback names, IP literals and this host's own name (resolving is
    already traffic, to the resolver). Names reserved never to resolve
    (RFC 2606/6761: .test, .invalid, .example, example.com/net/org) are
    answered NXDOMAIN here, without a lookup: the scraper's SSRF gate
    resolves every URL host, and fixtures use these names;
  * curl_cffi, whose libcurl opens its sockets in C where the `socket`
    patch never looks: `Session.request` / `AsyncSession.request` (under
    `curl_cffi.requests.request/get/post`) and, as the backstop under every
    curl_cffi API, `Curl.setopt(CurlOpt.URL, …)`.

Loopback (127.0.0.0/8, ::1, `localhost`) and AF_UNIX stay open: the stub
brokers, scrapers and upstreams the suite runs are all there.

Each refusal raises ExternalNetworkBlocked (a ConnectionRefusedError, so
code under test takes its normal network-failure path) and is recorded; the
autouse fixture in conftest fails the test on any record, so a broad
`except Exception` in the code under test cannot hide an attempt.

Not covered: subprocesses (the broker the lifecycle tests exec, shims run
as children). Those talk only to stubs the test wires up; the guard is about
this process.
"""
from __future__ import annotations

import contextlib
import ipaddress
import socket
import threading
from typing import NamedTuple
from urllib.parse import urlsplit


class ExternalNetworkBlocked(ConnectionRefusedError):
    pass


class Violation(NamedTuple):
    via: str
    target: str


def _norm(host) -> str:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return ""
    return host.strip().strip("[]").split("%", 1)[0].rstrip(".").lower()


def _ip(host: str):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


_RESERVED_SUFFIXES = ("test", "invalid", "example", "example.com", "example.net",
                      "example.org")


def _reserved(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in _RESERVED_SUFFIXES)


class _Guard:
    def __init__(self) -> None:
        self.violations: list[Violation] = []
        self._lock = threading.Lock()
        self._own_name = _norm(socket.gethostname())

    @staticmethod
    def is_loopback(host) -> bool:
        h = _norm(host)
        if h == "localhost":
            return True
        ip = _ip(h)
        return ip is not None and ip.is_loopback

    def _block(self, via: str, target) -> None:
        t = target if isinstance(target, str) else repr(target)
        with self._lock:
            self.violations.append(Violation(via, t))
        raise ExternalNetworkBlocked(
            f"test network guard: {via} to {t!r} refused — tests are hermetic, "
            "use a loopback stub")

    # --- checks -----------------------------------------------------------
    def check_address(self, sock, address, via: str) -> None:
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            return  # AF_UNIX paths, netlink, …
        host = address[0] if isinstance(address, tuple) and address else address
        if not self.is_loopback(host):
            self._block(via, _norm(host) or host)

    def check_name(self, host, via: str) -> None:
        h = _norm(host)
        if not h or self.is_loopback(h) or _ip(h) is not None or h == self._own_name:
            return  # no lookup leaves the host for these
        if _reserved(h):
            raise socket.gaierror(socket.EAI_NONAME,
                                  f"{h}: reserved name, answered locally by the test guard")
        self._block(via, h)

    def check_url(self, url, via: str) -> None:
        if isinstance(url, bytes):
            url = url.decode("utf-8", "replace")
        if not isinstance(url, str):
            return
        parts = urlsplit(url)
        if not parts.scheme:
            return  # relative to a base_url: the setopt backstop sees the full one
        host = parts.hostname or ""
        if not self.is_loopback(host):
            self._block(via, host or url)

    # --- for the guard's own tests -------------------------------------------
    @contextlib.contextmanager
    def expect_block(self, target: str):
        """Run the body, expect exactly-this-target refusals, and take them
        off the record so the autouse teardown does not fail the test."""
        mark = len(self.violations)
        with contextlib.suppress(Exception):
            yield
        new = self.violations[mark:]
        del self.violations[mark:]
        assert new, f"nothing refused for {target!r}: the guard let it through"
        assert all(v.target == target for v in new), new


GUARD = _Guard()


def _install() -> None:
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto

    def connect(self, address):
        GUARD.check_address(self, address, "socket.connect")
        return real_connect(self, address)

    def connect_ex(self, address):
        GUARD.check_address(self, address, "socket.connect_ex")
        return real_connect_ex(self, address)

    def sendto(self, data, *args):
        if args:
            GUARD.check_address(self, args[-1], "socket.sendto")
        return real_sendto(self, data, *args)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        real = getattr(socket, name)

        def resolver(host, *args, _real=real, _name=name, **kwargs):
            GUARD.check_name(host, f"socket.{_name}")
            return _real(host, *args, **kwargs)

        setattr(socket, name, resolver)

    try:
        from curl_cffi import Curl, CurlOpt
        from curl_cffi.requests import AsyncSession, Session
    except ImportError:  # pragma: no cover — curl_cffi is a hard dependency
        return

    real_setopt = Curl.setopt

    def setopt(self, option, value):
        if option == CurlOpt.URL:
            GUARD.check_url(value, "curl_cffi Curl.setopt(URL)")
        return real_setopt(self, option, value)

    Curl.setopt = setopt

    real_request = Session.request

    def request(self, method, url, *args, **kwargs):
        GUARD.check_url(url, "curl_cffi Session.request")
        return real_request(self, method, url, *args, **kwargs)

    Session.request = request

    real_arequest = AsyncSession.request

    async def arequest(self, method, url, *args, **kwargs):
        GUARD.check_url(url, "curl_cffi AsyncSession.request")
        return await real_arequest(self, method, url, *args, **kwargs)

    AsyncSession.request = arequest


_install()
