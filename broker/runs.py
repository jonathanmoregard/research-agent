"""Per-run state: token, URL ledger, budgets, browser sessions.

In memory only. A broker restart forgets every run; the shims then answer
"run not registered (broker restarted)" and the agent finishes with what it
has (docs/egress-broker.md §2.5).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

from broker import config
from scraper import urlpolicy


class RouteError(Exception):
    """A refusal or failure the shim shows the model as the tool result."""

    def __init__(self, status: int, message: str, reason: str = "", **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.reason = reason or message.split(":")[0][:60]
        self.extra = extra


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class Run:
    run_id: str
    token_hash: str
    depth: str
    provider: str
    created: float
    expires: float
    ledger: urlpolicy.Ledger = field(
        default_factory=lambda: urlpolicy.Ledger(max_urls=config.LEDGER_MAX_URLS))
    budgets: Counter = field(default_factory=Counter)
    typed_chars: int = 0
    browser_actions: int = 0
    drags: int = 0
    xy_targets: int = 0
    # sid -> session viewport (for coordinate snapping)
    sessions: dict[str, dict] = field(default_factory=dict)
    refusals: Counter = field(default_factory=Counter)
    # marketplace etiquette: last call time and a closed-for-run reason
    market_last: dict[str, float] = field(default_factory=dict)
    market_closed: dict[str, str] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # --- budgets ---------------------------------------------------------
    def spend(self, route: str) -> None:
        limit = config.ROUTE_BUDGETS[route][self.depth]
        with self.lock:
            if self.budgets[route] >= limit:
                raise RouteError(429, f"{route} budget for this run exhausted "
                                      f"({limit} calls). Do not retry; work with "
                                      "the results you have.", "budget")
            self.budgets[route] += 1

    def spend_browser(self, actions: int, typed: int = 0, drags: int = 0,
                      xy: int = 0) -> None:
        """Charge browser actions, typed chars and coordinate use together,
        all or nothing, so a refused call costs nothing."""
        with self.lock:
            if self.browser_actions + actions > config.BROWSER_ACTIONS[self.depth]:
                raise RouteError(429, "browser-action budget for this run exhausted "
                                      f"({config.BROWSER_ACTIONS[self.depth]} actions)",
                                 "browser_actions")
            if self.typed_chars + typed > config.TYPED_CHARS[self.depth]:
                raise RouteError(429, "typed-text budget for this run exhausted "
                                      f"({config.TYPED_CHARS[self.depth]} chars)",
                                 "typed_budget")
            if self.drags + drags > config.MAX_DRAGS_PER_RUN:
                raise RouteError(429, f"drag budget for this run exhausted "
                                      f"({config.MAX_DRAGS_PER_RUN} drags)", "drags")
            if self.xy_targets + xy > config.MAX_XY_TARGETS_PER_RUN:
                raise RouteError(
                    429, "raw x,y target budget for this run exhausted "
                         f"({config.MAX_XY_TARGETS_PER_RUN}); target elements by "
                         "{ref:'eN'} from the snapshot (or a CSS selector) instead",
                    "xy_targets")
            self.browser_actions += actions
            self.typed_chars += typed
            self.drags += drags
            self.xy_targets += xy

    # --- ledger -----------------------------------------------------------
    def harvest(self, urls) -> int:
        with self.lock:
            before = self.ledger.full
            n = self.ledger.add_urls(urls)
            if self.ledger.full and not before:
                log(f"run={self.run_id} ledger full at {len(self.ledger)} URLs")
            return n

    def check(self, url: str) -> urlpolicy.Verdict:
        with self.lock:
            return urlpolicy.check(url, self.ledger)

    def nav_policy(self, extra: list[str] = ()) -> dict:
        with self.lock:
            urls = [u for u in (urlpolicy.normalize(x) for x in extra) if u]
            urls += self.ledger.recent(config.NAV_POLICY_MAX_URLS - len(urls))
        return {"urls": urls, "templates": True}

    def refuse(self, reason: str) -> None:
        with self.lock:
            self.refusals[reason] += 1

    def summary(self) -> dict:
        with self.lock:
            return {
                "run_id": self.run_id, "depth": self.depth, "provider": self.provider,
                "calls": dict(self.budgets), "refusals": dict(self.refusals),
                "typed_chars": self.typed_chars, "browser_actions": self.browser_actions,
                "drags": self.drags, "xy_targets": self.xy_targets,
                "ledger": len(self.ledger), "ledger_full": self.ledger.full,
                "age_s": int(time.time() - self.created),
            }


def log(line: str) -> None:
    import sys
    sys.stderr.write(f"[broker] {line}\n")
    sys.stderr.flush()


class Registry:
    """Live runs, by token hash and by run id. Thread-safe."""

    def __init__(self, clock=time.time):
        self._lock = threading.Lock()
        self._by_hash: dict[str, Run] = {}
        self._clock = clock

    def register(self, run_id: str, depth: str, provider: str,
                 prompt_urls: list[str], ttl_s: float) -> tuple[str, Run]:
        token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        now = self._clock()
        run = Run(run_id=run_id, token_hash=token_hash(token), depth=depth,
                  provider=provider, created=now,
                  expires=now + min(float(ttl_s), config.MAX_RUN_TTL_S))
        run.harvest(prompt_urls)
        with self._lock:
            self._by_hash[run.token_hash] = run
        return token, run

    def lookup(self, token: str) -> Run | None:
        h = token_hash(token)
        with self._lock:
            for known, run in self._by_hash.items():
                if hmac.compare_digest(known, h):
                    if run.expires < self._clock():
                        return None
                    return run
        return None

    def adopt(self, run: Run) -> None:
        """A run restored from saved state (token hash only; no token)."""
        with self._lock:
            self._by_hash[run.token_hash] = run

    def all(self) -> list[Run]:
        with self._lock:
            return list(self._by_hash.values())

    def by_run_id(self, run_id: str) -> list[Run]:
        with self._lock:
            return [r for r in self._by_hash.values() if r.run_id == run_id]

    def remove(self, run: Run) -> None:
        with self._lock:
            self._by_hash.pop(run.token_hash, None)

    def expired(self) -> list[Run]:
        now = self._clock()
        with self._lock:
            return [r for r in self._by_hash.values() if r.expires < now]

    def active(self) -> int:
        with self._lock:
            return len(self._by_hash)

    def owner_of(self, sid: str) -> Run | None:
        with self._lock:
            runs = list(self._by_hash.values())
        for run in runs:
            with run.lock:
                if sid in run.sessions:
                    return run
        return None
