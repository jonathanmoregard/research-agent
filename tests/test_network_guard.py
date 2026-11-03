"""The suite-wide network guard fires (docs/egress-broker.md §8.1).

Standing directive: no test, locally or in CI, opens a real network
connection. tests/conftest.py enforces it for Python sockets and for
curl_cffi, whose libcurl opens sockets in C where a `socket` patch never
looks. Every target here is refused before any packet: the guard checks the
address, not the outcome. 192.0.2.0/24 is TEST-NET-1 (RFC 5737); the named
target is the real one T-1 reached (§8.1).
"""
from __future__ import annotations

import socket
import threading
import urllib.request

import pytest

OUTSIDE_IP = "192.0.2.7"
OUTSIDE_HOST = "api.exa.ai"
OUTSIDE_URL = f"https://{OUTSIDE_HOST}/search"


def test_socket_connect_to_a_non_loopback_address_is_refused(network_guard):
    for connect in ("connect", "connect_ex"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with network_guard.expect_block(OUTSIDE_IP):
                getattr(s, connect)((OUTSIDE_IP, 443))
        finally:
            s.close()


def test_ipv6_and_hostnames_are_refused_without_resolving(network_guard):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        with network_guard.expect_block("2001:db8::1"):
            s.connect(("2001:db8::1", 443, 0, 0))
    finally:
        s.close()
    with network_guard.expect_block(OUTSIDE_HOST):
        socket.getaddrinfo(OUTSIDE_HOST, 443)
    with network_guard.expect_block(OUTSIDE_HOST):
        socket.gethostbyname(OUTSIDE_HOST)


@pytest.mark.parametrize("name", ["x.test", "exa.invalid", "example.com", "shop.example"])
def test_reserved_names_are_nxdomain_without_a_lookup(network_guard, name):
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(name, 443)
    assert network_guard.violations == []


def test_urllib_to_the_outside_is_refused(network_guard):
    with network_guard.expect_block(OUTSIDE_HOST):
        urllib.request.urlopen(OUTSIDE_URL, timeout=1)


def test_udp_sendto_the_outside_is_refused(network_guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with network_guard.expect_block(OUTSIDE_IP):
            s.sendto(b"x", (OUTSIDE_IP, 53))
    finally:
        s.close()


def test_curl_cffi_module_functions_and_sessions_are_refused(network_guard):
    from curl_cffi import requests as cfrequests

    for call in (lambda: cfrequests.post(OUTSIDE_URL, json={}, timeout=1),
                 lambda: cfrequests.get(OUTSIDE_URL, timeout=1),
                 lambda: cfrequests.request("GET", OUTSIDE_URL, timeout=1),
                 lambda: cfrequests.Session().request("GET", OUTSIDE_URL, timeout=1)):
        with network_guard.expect_block(OUTSIDE_HOST):
            call()


def test_raw_curl_handle_is_refused_at_setopt(network_guard):
    """The backstop under every curl_cffi API: the URL option itself."""
    from curl_cffi import Curl, CurlOpt

    c = Curl()
    try:
        with network_guard.expect_block(OUTSIDE_IP):
            c.setopt(CurlOpt.URL, f"http://{OUTSIDE_IP}/".encode())
    finally:
        c.close()


def test_a_swallowed_block_still_fails_the_test(network_guard):
    """Code under test often catches Exception and reports "unavailable";
    the guard records every attempt, and the teardown fails the test on any
    record, caught or not."""
    s = socket.socket()
    try:
        try:
            s.connect((OUTSIDE_IP, 80))
        except Exception:
            pass  # what a broad handler in production code does
    finally:
        s.close()
    assert [v.target for v in network_guard.violations] == [OUTSIDE_IP]
    network_guard.violations.clear()  # this test expected it


def test_loopback_and_unix_sockets_stay_allowed(network_guard, tmp_path):
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        pass
    srv.close()
    assert socket.getaddrinfo("localhost", 80)
    path = str(tmp_path / "s.sock")
    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    u.bind(path)
    u.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(path)
    c.close()
    u.close()
    assert network_guard.violations == []


def test_curl_cffi_to_loopback_stays_allowed(network_guard):
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        from curl_cffi import requests as cfrequests
        r = cfrequests.get(f"http://127.0.0.1:{srv.server_address[1]}/", timeout=5)
        assert r.status_code == 204
    finally:
        srv.shutdown()
        srv.server_close()
    assert network_guard.violations == []


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "localhost", "LOCALHOST"])
def test_loopback_names(network_guard, host):
    assert network_guard.is_loopback(host)


@pytest.mark.parametrize("host", ["10.0.2.2", "0.0.0.0", "192.0.2.7", "localhost.evil.example",
                                  "api.exa.ai", "", None])
def test_non_loopback_names(network_guard, host):
    assert not network_guard.is_loopback(host)
