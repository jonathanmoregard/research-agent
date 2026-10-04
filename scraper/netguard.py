"""Destination gate for every URL the scraper's chromium is pointed at.

The scraper VM reaches the network through QEMU SLIRP, where 10.0.2.2 is
the HOST's loopback. Without this gate `render_page("http://10.0.2.2:<port>")`
returned the body of any service listening on the host's 127.0.0.1. So any
destination that is not a public unicast address is refused: loopback,
link-local / IMDS, RFC1918 (incl. the SLIRP 10.0.2.0/24 net), CGNAT,
benchmarking, multicast, reserved, and their IPv6 / IPv4-mapped forms.

Layers, outermost first:
  1. The HTTP API checks the requested URL (and every goto action) before
     chromium starts (`is_blocked_url`).
  2. `install_request_guard` routes every request the browser context
     issues (subresources, XHR/fetch, frames, form posts) through the same
     check and aborts blocked ones.
  3. Playwright does NOT route redirect hops (verified: a 302 to another
     host is followed without the route handler seeing it), so after every
     navigation `blocked_hop` walks the redirect chain and the final URL;
     a hit means the content is withheld from the caller.
  4. The hard guarantee lives below Python: the scraper guest's nftables
     output chain drops new connections to the host gateway and private
     ranges (nixos-config modules/nixos/scraper-microvm.nix). DNS
     rebinding between our lookup and chromium's, websockets, and redirect
     hops are only fully covered there.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",         # "this network"
        "10.0.0.0/8",        # RFC1918 — includes SLIRP 10.0.2.0/24 (10.0.2.2 = host loopback)
        "100.64.0.0/10",     # CGNAT / Tailscale
        "127.0.0.0/8",       # loopback
        "169.254.0.0/16",    # link-local (cloud IMDS)
        "172.16.0.0/12",     # RFC1918
        "192.0.0.0/24",      # IETF protocol assignments
        "192.0.2.0/24",      # TEST-NET-1
        "192.168.0.0/16",    # RFC1918
        "198.18.0.0/15",     # benchmarking
        "198.51.100.0/24",   # TEST-NET-2
        "203.0.113.0/24",    # TEST-NET-3
        "224.0.0.0/4",       # multicast
        "240.0.0.0/4",       # reserved + broadcast
        "::/128",            # unspecified
        "::1/128",           # loopback v6
        "64:ff9b::/96",      # NAT64 (embeds an IPv4 address)
        "64:ff9b:1::/48",    # local-use NAT64
        "100::/64",          # discard
        "2001:db8::/32",     # documentation
        "fc00::/7",          # unique-local
        "fe80::/10",         # link-local v6
        "fec0::/10",         # deprecated site-local (QEMU SLIRP's v6 net)
        "ff00::/8",          # multicast v6
    )
]


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True unless `ip` is a public unicast address."""
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv4 smuggled inside IPv6 is judged as the IPv4 it carries.
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None and is_blocked_ip(embedded):
            return True
    if any(ip in net for net in BLOCKED_NETS if net.version == ip.version):
        return True
    return not ip.is_global


def _literal_ip(host: str):
    # Literal IPv4 in every historic form inet_aton (and chromium's URL
    # parser) accepts: "127.1", "0x7f000001", "017700000001", "2130706433".
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        pass
    try:
        return ipaddress.IPv6Address(
            socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
        )
    except OSError:
        return None


def is_blocked_host(host: str) -> bool:
    """True if host is, or resolves to ANY address that is, not public.

    Every A/AAAA answer is checked, so a name with one public and one
    private answer is refused. Chromium does its own lookup afterwards, so
    a rebinding resolver can still race this check; the guest firewall is
    what closes that gap.
    """
    host = host.strip("[]").rstrip(".").lower()
    if not host:
        return True
    lit = _literal_ip(host)
    if lit is not None:
        return is_blocked_ip(lit)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        # Unresolvable: chromium fails with NXDOMAIN downstream.
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            return True
        if is_blocked_ip(ip):
            return True
    return False


def is_blocked_url(url: str) -> bool:
    """True if url is http(s) to a blocked host, or not http(s) at all."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return True
    if parsed.scheme not in ("http", "https"):
        return True
    return is_blocked_host(parsed.hostname or "")


def _browser_internal(url: str) -> bool:
    # Requests that never touch the network: inline data, blobs the page
    # built itself, about:blank.
    return url.startswith(("data:", "blob:", "about:"))


def _main_frame_navigation(request) -> bool:
    try:
        if not request.is_navigation_request():
            return False
        return request.frame.parent_frame is None
    except Exception:
        # Service-worker and other frameless requests are not navigations.
        return False


def install_request_guard(context, nav_allowed=None, on_blocked_nav=None) -> None:
    """Abort every request from `context` whose destination is blocked.

    With `nav_allowed` (a URL -> bool predicate, the run's provenance gate),
    every top-level navigation is checked too — goto, link clicks, JS
    `location` changes, form submits — and only GET navigations pass: a
    form POST would carry whatever the agent typed to the page's server.
    `on_blocked_nav(url)` is told about each refused navigation. A
    refused navigation is answered locally with 204, so the page stays put.

    Subresources and iframes stay ungated. That is NOT because they are
    harmless: once the agent has typed into a page, that page's script can
    send the typed text anywhere in a fetch/beacon. Gating subresources
    would not stop that (the script can encode it in any request it is
    allowed to make), so the controls are upstream instead: the broker
    bounds typed text per call and per run, and snaps every number the
    model chooses (docs/egress-broker.md §0.1, §3.5, §3.6). This gate's job
    is catching a navigation the broker did not vet.
    """
    verdicts: dict[str, bool] = {}

    def handler(route):
        url = route.request.url
        if _browser_internal(url):
            route.continue_()
            return
        if nav_allowed is not None and _main_frame_navigation(route.request):
            if route.request.method != "GET" or not nav_allowed(url):
                if on_blocked_nav is not None:
                    try:
                        on_blocked_nav(url)
                    except Exception:
                        pass
                # Answered locally with 204 No Content: nothing leaves the
                # browser, and chromium keeps the current page (an abort
                # would leave it on chrome-error://). Verified in real
                # chromium for link clicks, JS location changes and forms.
                route.fulfill(status=204, body="")
                return
        try:
            host = (urlparse(url).hostname or "").lower()
            scheme_ok = urlparse(url).scheme in ("http", "https", "ws", "wss")
        except ValueError:
            host, scheme_ok = "", False
        if not scheme_ok:
            route.abort("blockedbyclient")
            return
        if host not in verdicts:
            verdicts[host] = is_blocked_host(host)
        if verdicts[host]:
            route.abort("blockedbyclient")
        else:
            route.continue_()

    context.route("**/*", handler)


def blocked_hop(response, final_url: str) -> str | None:
    """First blocked URL among a navigation's redirect chain + final URL."""
    urls = [final_url]
    req = response.request if response is not None else None
    while req is not None:
        urls.append(req.url)
        req = req.redirected_from
    for u in urls:
        if u and not _browser_internal(u) and is_blocked_url(u):
            return u
    return None
