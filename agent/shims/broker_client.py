"""Shim side of the egress broker (docs/egress-broker.md §2.4, §2.6, §4.4, §12.4).

Dual mode: a shim whose environment has RESEARCH_BROKER_TOKEN posts to its
broker route with that token; without it, the shim keeps today's direct path
(deleted in the cleanup PR). The broker holds every key and derives the run
from the token — a shim never sends a key or a run id.

Stdlib only: it runs in the agent jail under the guest's python3.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_URL = "http://10.0.2.2:8124"
# §2.3 shim waits, mirrored from broker/config.py (the jail cannot import it;
# tests/test_shim_broker_mode.py pins the two together).
KEYED_TIMEOUT_S = 45.0
SCRAPER_TIMEOUT_S = {
    "render": 115.0,
    "intercept": 115.0,
    "open": 150.0,
    "act": 180.0,
    "screenshot": 150.0,
    "save_artifact": 150.0,
    "close": 150.0,
}
# §12.2: a request that lands in a broker reload queues in the systemd-held
# backlog for the drain (TimeoutStopSec=210) plus the new process's start.
# That is latency, never an error.
RELOAD_ALLOWANCE_S = 220.0
MAX_REPLY_BYTES = 8 * 1024 * 1024
UNAVAILABLE = "broker unavailable (infra)"


class BrokerError(RuntimeError):
    """The broker's message, shown to the model as the tool result (§3.8).

    `upstream_body` is remote text (an API error body). It is kept apart from
    the message so a shim shows it only inside the untrusted wrap.
    """

    def __init__(self, message: str, status: int = 0, upstream_body: str = ""):
        super().__init__(message)
        self.status = status
        self.upstream_body = upstream_body


def enabled() -> bool:
    return bool(os.environ.get("RESEARCH_BROKER_TOKEN"))


# No proxy, ever: the token must only go to the broker.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post(path: str, body: dict, timeout_s: float,
         max_bytes: int = MAX_REPLY_BYTES) -> dict:
    """POST one broker route. Returns the reply dict (status ok) or raises
    BrokerError with the broker's own wording (§2.6)."""
    base = os.environ.get("RESEARCH_BROKER_URL") or DEFAULT_URL
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('RESEARCH_BROKER_TOKEN', '')}",
        },
    )
    try:
        with _OPENER.open(req, timeout=timeout_s + RELOAD_ALLOWANCE_S) as resp:
            status, raw = resp.status, resp.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            raw = e.read(64 * 1024)
        except OSError:
            raw = b""
    except (urllib.error.URLError, OSError):
        raise BrokerError(UNAVAILABLE) from None
    if len(raw) > max_bytes:
        raise BrokerError("broker response too large")
    try:
        reply = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        reply = None
    if not isinstance(reply, dict):
        # Not the broker talking (it always answers JSON).
        raise BrokerError(UNAVAILABLE, status)
    if status != 200 or reply.get("status") != "ok":
        msg = reply.get("error")
        body = reply.get("upstream_body")
        raise BrokerError(msg if isinstance(msg, str) and msg else f"broker HTTP {status}",
                          status, body if isinstance(body, str) else "")
    return reply
