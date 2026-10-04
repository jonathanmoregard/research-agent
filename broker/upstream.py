"""Upstream HTTP for the keyed routes: transport, credentials, OAuth cache.

The transport is a plain function so tests substitute it; nothing here can
change a route's host, path or method (those are constants in the route
modules).
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from broker import config
from broker.runs import Run, RouteError

MAX_UPSTREAM_BYTES = 4 * 1024 * 1024
USER_AGENT = "research-agent-broker/1.0 (personal read-only search)"


class TransportError(Exception):
    """No HTTP answer: timeout or network failure. Message is fixed text."""


# (method, url, headers, body, timeout_s, impersonate) -> (status, body)
Transport = Callable[[str, str, dict, "bytes | None", float, bool], "tuple[int, bytes]"]


def curl_transport(method: str, url: str, headers: dict, body: bytes | None,
                   timeout_s: float, impersonate: bool) -> tuple[int, bytes]:
    """curl_cffi: Exa's and EUIPO's WAFs reject stdlib TLS fingerprints."""
    from curl_cffi import requests as cfrequests  # type: ignore

    try:
        r = cfrequests.request(
            method, url, headers=headers, data=body, timeout=timeout_s,
            impersonate="chrome" if impersonate else None,
            allow_redirects=False,
        )
    except Exception as e:  # curl_cffi raises its own hierarchy
        name = type(e).__name__.lower()
        raise TransportError("timeout" if "timeout" in name else "network error") from None
    data = r.content or b""
    if len(data) > MAX_UPSTREAM_BYTES:
        raise TransportError("response too large")
    return r.status_code, data


def load_credentials(directory: str | None = None) -> dict[str, str]:
    """$CREDENTIALS_DIRECTORY/<name> for each LoadCredential name.

    A missing or empty file (an agenix placeholder) reads as "" and that
    API answers 503 "<API> not configured". Never from the environment.
    """
    directory = directory if directory is not None else os.environ.get("CREDENTIALS_DIRECTORY", "")
    out: dict[str, str] = {}
    for name in config.CREDENTIAL_NAMES:
        value = ""
        if directory:
            try:
                with open(os.path.join(directory, name), encoding="utf-8") as f:
                    value = f.read().strip()
            except OSError:
                value = ""
        out[name] = value
    return out


@dataclass
class TokenCache:
    """An OAuth client-credentials access token, in broker memory only.

    Never returned to the VM; a refresh-token field in the mint response is
    ignored (client_credentials grants should not carry one).
    """

    token: str = ""
    exp: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def get(self, mint: Callable[[], tuple[str, float]], clock=time.time) -> str:
        with self.lock:
            now = clock()
            if self.token and now < self.exp:
                return self.token
            token, ttl = mint()
            self.token = token
            self.exp = now + max(30.0, ttl - 60.0)
            return token

    def clear(self) -> None:
        with self.lock:
            self.token, self.exp = "", 0.0


@dataclass
class Ctx:
    """Everything one keyed-route call needs."""

    run: Run
    creds: dict
    transport: Transport
    deadline: float  # time.monotonic() by which the whole route must answer
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic

    def remaining(self, cap: float) -> float:
        left = self.deadline - self.clock()
        if left <= 0.5:
            raise RouteError(504, "timeout (broker route deadline)", "timeout")
        return min(cap, left)


def call(ctx: Ctx, api: str, method: str, url: str, headers: dict,
         body: bytes | None = None, impersonate: bool = False,
         cap_s: float = config.KEYED_UPSTREAM_TIMEOUT_S) -> tuple[int, bytes]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **headers}
    try:
        return ctx.transport(method, url, headers, body, ctx.remaining(cap_s), impersonate)
    except TransportError as e:
        raise RouteError(502, f"{api} {e}", "upstream") from None


def parse_json(api: str, data: bytes):
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        raise RouteError(502, f"{api} returned non-JSON", "upstream") from None


def clip(value, limit: int) -> str:
    s = " ".join(str(value or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def upstream_error(api: str, status: int, data: bytes) -> RouteError:
    """502 with the API's status; the body (remote text) travels separately
    and the shim shows it only inside the untrusted wrap."""
    return RouteError(502, f"{api} HTTP {status}", "upstream", upstream_status=status,
                      upstream_body=clip(data.decode("utf-8", errors="replace"), 300))
