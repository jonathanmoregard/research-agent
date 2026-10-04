#!/usr/bin/env python3
"""research-broker: host-side credential-injecting egress broker.

The research VM holds no third-party key. Every keyed API call (Exa,
Tavily, eBay, Tradera, EUIPO) and every scraper call goes through here:
the broker injects the key or the scraper bearer itself, gates every
model-authored URL against the run's ledger, and feeds the ledger from what
it returns. Design: docs/egress-broker.md.

Listeners (systemd socket activation, told apart by $LISTEN_FDNAMES):
  vm     TCP 127.0.0.1:8124 — the research VM (10.0.2.2:8124 via SLIRP).
         Every /v1 route needs `Authorization: Bearer <run token>`.
  admin  /run/research-broker/admin.sock (0600 jonathan) — the host MCP
         server registers and deregisters runs here.

Run as `python3 -I -B /run/rb/broker/server.py`: isolated mode, so the
directory holding broker/ and scraper/ is put on sys.path here, and only
that directory (in production it holds exactly those two read-only binds).

Lifecycle:
  * SIGTERM drains: stop accepting (systemd keeps queueing on the held
    sockets), finish in-flight requests (never orphan a scraper command),
    write the live runs to $STATE_DIRECTORY, exit 0. The next start loads
    them, so a restart mid-run is invisible to the run.
  * Code reload: at each registration, if the code on disk changed and no
    run is active, answer 503 "restarting" and exit 0; the next connection
    starts the new code. The MCP server retries once.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import signal  # noqa: E402
import socket  # noqa: E402
import socketserver  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from broker import config, marketplaces, scraper_proxy, search, trademark, upstream  # noqa: E402
from broker.runs import Registry, RouteError, Run, log  # noqa: E402
from scraper import urlpolicy  # noqa: E402

KEYED_ROUTES = {
    "/v1/exa/search": ("exa", search.exa_search),
    "/v1/tavily/search": ("tavily", search.tavily_search),
    "/v1/ebay/search": ("ebay", marketplaces.ebay_search),
    "/v1/tradera/search": ("tradera", marketplaces.tradera_search),
    "/v1/euipo/search": ("euipo", trademark.euipo_search),
}
_SESSION_PATH = re.compile(r"^/v1/scraper/session/([a-f0-9]{16})/(act|screenshot|save_artifact|close)$")
_ADMIN_RUN_PATH = re.compile(r"^/admin/runs/([a-f0-9]{32})$")
_RUN_ID_RE = re.compile(r"^[a-f0-9]{32}$")
STATE_FILE = "runs.json"
STATE_VERSION = 1
MAX_PROMPT_URLS = urlpolicy.MAX_URLS_PER_TEXT


def code_digest(root: str = _ROOT) -> str:
    """Hash of the code this process would load (broker/*.py + urlpolicy)."""
    h = hashlib.sha256()
    files = sorted(os.path.join(root, "broker", f)
                   for f in os.listdir(os.path.join(root, "broker")) if f.endswith(".py"))
    files.append(os.path.join(root, "scraper", "urlpolicy.py"))
    for path in files:
        try:
            with open(path, "rb") as f:
                h.update(path.encode() + b"\0" + f.read() + b"\0")
        except OSError:
            h.update(path.encode() + b"\0missing\0")
    return h.hexdigest()


class Broker:
    """Everything request handling needs; no sockets (tests drive it directly)."""

    def __init__(self, creds: dict[str, str], transport=upstream.curl_transport,
                 scraper: scraper_proxy.Scraper | None = None,
                 registry: Registry | None = None, state_dir: str | None = None,
                 code_root: str = _ROOT, sleep=time.sleep):
        self.creds = creds
        self.transport = transport
        self.scraper = scraper or scraper_proxy.Scraper()
        self.registry = registry or Registry()
        self.state_dir = state_dir
        self.code_root = code_root
        self.loaded_digest = code_digest(code_root)
        self.sleep = sleep
        self.exit_requested = threading.Event()
        self._sems = {name: threading.BoundedSemaphore(config.UPSTREAM_CONCURRENCY)
                      for name in list(config.ROUTE_BUDGETS)}

    # --- secrets never leave ------------------------------------------------
    def scrub(self, text: str) -> str:
        secrets = [v for v in self.creds.values() if v and len(v) >= 6]
        secrets += [c.token for c in (marketplaces.EBAY_TOKEN, trademark.EUIPO_TOKEN) if c.token]
        for s in secrets:
            if s in text:
                text = text.replace(s, "[redacted]")
        return text

    # --- VM listener ----------------------------------------------------------
    def handle_vm(self, method: str, path: str, auth: str, body: dict | None
                  ) -> tuple[int, dict, Run | None, str]:
        """Returns (status, reply, run, reason)."""
        if method == "GET" and path == "/v1/health":
            return 200, {"status": "ok"}, None, ""
        if method != "POST" or not (path in KEYED_ROUTES or path.startswith("/v1/scraper/")):
            return 404, {"status": "error", "error": "not found"}, None, "not_found"
        token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""
        run = self.registry.lookup(token) if token else None
        if run is None:
            return 401, {"status": "error", "error": (
                "run not registered (broker restarted or the run ended) — finish "
                "with what you have")}, None, "unauthenticated"
        if body is None:
            return 400, {"status": "error", "error": "bad json"}, run, "bad_request"
        try:
            return 200, dict(self._dispatch(run, path, body), status="ok"), run, ""
        except RouteError as e:
            run.refuse(e.reason)
            return e.status, dict(e.extra, status="error", error=e.message), run, e.reason

    def _dispatch(self, run: Run, path: str, body: dict) -> dict:
        if path in KEYED_ROUTES:
            name, fn = KEYED_ROUTES[path]
            ctx = upstream.Ctx(run=run, creds=self.creds, transport=self.transport,
                               deadline=time.monotonic() + config.KEYED_ROUTE_DEADLINE_S,
                               sleep=self.sleep)
            return self._limited(name, lambda: fn(ctx, body))
        sp, sc = scraper_proxy, self.scraper
        if path == "/v1/scraper/render":
            return self._limited("render", lambda: sp.render(sc, run, body))
        if path == "/v1/scraper/intercept":
            return self._limited("render", lambda: sp.intercept(sc, run, body))
        if path == "/v1/scraper/session/open":
            return self._limited("browse", lambda: sp.session_open(sc, run, body))
        m = _SESSION_PATH.match(path)
        if m:
            sid, op = m.group(1), m.group(2)
            if op == "act":
                return self._limited("browse", lambda: sp.session_act(
                    sc, run, sid, body, self.registry.owner_of))
            return sp.session_op(sc, run, sid, op, body, self.registry.owner_of)
        raise RouteError(404, "not found", "not_found")

    def _limited(self, name: str, fn):
        sem = self._sems[name]
        if not sem.acquire(timeout=config.KEYED_ROUTE_DEADLINE_S):
            raise RouteError(503, f"{name}: broker busy, retry shortly", "busy")
        try:
            return fn()
        finally:
            sem.release()

    # --- admin listener ---------------------------------------------------------
    def handle_admin(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        if method == "GET" and path == "/admin/health":
            return 200, {"status": "ok", "active_runs": self.registry.active(),
                         "code_stale": code_digest(self.code_root) != self.loaded_digest}
        if method == "POST" and path == "/admin/runs":
            return self._register(body)
        m = _ADMIN_RUN_PATH.match(path)
        if method == "DELETE" and m:
            return 200, {"status": "ok", "summaries": self.deregister(m.group(1))}
        return 404, {"status": "error", "error": "not found"}

    def _register(self, body: dict | None) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return 400, {"status": "error", "error": "bad json"}
        run_id, depth = body.get("run_id"), body.get("depth")
        provider, ttl = body.get("provider", "claude"), body.get("ttl_s")
        urls = body.get("prompt_urls", [])
        if not (isinstance(run_id, str) and _RUN_ID_RE.match(run_id)):
            return 400, {"status": "error", "error": "bad run_id"}
        if depth not in config.DEPTHS or provider not in ("claude", "codex"):
            return 400, {"status": "error", "error": "bad depth or provider"}
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
            return 400, {"status": "error", "error": "bad ttl_s"}
        if not isinstance(urls, list) or len(urls) > MAX_PROMPT_URLS \
                or not all(isinstance(u, str) for u in urls):
            return 400, {"status": "error", "error": "bad prompt_urls"}
        if code_digest(self.code_root) != self.loaded_digest and self.registry.active() == 0:
            # Pulled code and nothing in flight: restart onto it.
            self.exit_requested.set()
            return 503, {"status": "error", "error": "restarting"}
        token, run = self.registry.register(run_id, depth, provider, urls, float(ttl))
        log(f"run={run_id} registered depth={depth} provider={provider} "
            f"prompt_urls={len(urls)} ttl_s={int(ttl)}")
        return 200, {"status": "ok", "token": token}

    def deregister(self, run_id: str) -> list[dict]:
        out = []
        for run in self.registry.by_run_id(run_id):
            self.registry.remove(run)
            scraper_proxy.close_all(self.scraper, run)
            summary = run.summary()
            log("run summary " + json.dumps(summary, sort_keys=True))
            out.append(summary)
        return out

    def sweep(self) -> None:
        for run in self.registry.expired():
            log(f"run={run.run_id} expired (TTL)")
            self.deregister(run.run_id)

    # --- restart-safe state -----------------------------------------------------
    def save_state(self) -> None:
        if not self.state_dir:
            return
        runs = []
        for run in self.registry.all():
            with run.lock:
                runs.append({
                    "run_id": run.run_id, "token_hash": run.token_hash, "depth": run.depth,
                    "provider": run.provider, "created": run.created,
                    "expires": run.expires, "ledger": run.ledger.recent(len(run.ledger))[::-1],
                    "ledger_full": run.ledger.full, "budgets": dict(run.budgets),
                    "typed_chars": run.typed_chars, "browser_actions": run.browser_actions,
                    "drags": run.drags, "xy_targets": run.xy_targets,
                    "sessions": run.sessions, "refusals": dict(run.refusals),
                    "market_closed": run.market_closed,
                })
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, prefix=".runs.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": STATE_VERSION, "runs": runs}, f)
        os.replace(tmp, os.path.join(self.state_dir, STATE_FILE))
        log(f"state saved: {len(runs)} run(s)")

    def load_state(self) -> None:
        if not self.state_dir:
            return
        path = os.path.join(self.state_dir, STATE_FILE)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        finally:
            try:
                os.unlink(path)  # load once; a crash after this loses runs, not tokens
            except OSError:
                pass
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return
        now = time.time()
        loaded = 0
        for r in data.get("runs") or []:
            try:
                if r["expires"] < now or r["depth"] not in config.DEPTHS:
                    continue
                run = Run(run_id=r["run_id"], token_hash=r["token_hash"], depth=r["depth"],
                          provider=r["provider"], created=r["created"], expires=r["expires"])
                run.ledger.add_urls(r.get("ledger") or [])
                run.ledger.full = bool(r.get("ledger_full"))
                run.budgets.update(r.get("budgets") or {})
                run.typed_chars = int(r.get("typed_chars", 0))
                run.browser_actions = int(r.get("browser_actions", 0))
                run.drags = int(r.get("drags", 0))
                run.xy_targets = int(r.get("xy_targets", 0))
                run.sessions = {k: v for k, v in (r.get("sessions") or {}).items()
                                if isinstance(v, dict)}
                run.refusals.update(r.get("refusals") or {})
                run.market_closed = dict(r.get("market_closed") or {})
            except (KeyError, TypeError, ValueError):
                continue
            self.registry.adopt(run)
            loaded += 1
        log(f"state loaded: {loaded} run(s)")


# --- HTTP plumbing ---------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "research-broker"
    sys_version = ""
    timeout = 15  # slowloris bound on reads; long upstream waits happen between reads
    app: Broker

    def address_string(self) -> str:  # AF_UNIX peers have no address
        ca = self.client_address
        return ca[0] if isinstance(ca, tuple) and ca else "unix"

    def _reply(self, status: int, body: dict) -> None:
        data = self.app.scrub(json.dumps(body, ensure_ascii=False)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self, cap: int) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > cap:
            return None
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return body if isinstance(body, dict) else None

    def log_message(self, format, *args):  # noqa: A002 — per-request line is ours
        pass


class VMHandler(_Handler):
    def _handle(self) -> None:
        t0 = time.monotonic()
        path = self.path.split("?", 1)[0]
        big = path.endswith("/act") or path == "/v1/scraper/intercept"
        body = self._body(config.MAX_BROWSER_BODY_BYTES if big else config.MAX_BODY_BYTES) \
            if self.command == "POST" else {}
        status, reply, run, reason = self.app.handle_vm(
            self.command, path, self.headers.get("Authorization", ""), body)
        self._reply(status, reply)
        if path != "/v1/health":
            detail = reply.get("error", "") if status != 200 else ""
            log(f"run={run.run_id if run else '-'} {self.command} {path} {status} "
                f"reason={reason or '-'} upstream={reply.get('upstream_status', '-')} "
                f"ms={int((time.monotonic() - t0) * 1000)}"
                + (f" detail={self.app.scrub(str(detail))[:300]!r}" if detail else ""))

    do_GET = do_POST = do_DELETE = _handle


class AdminHandler(_Handler):
    def _handle(self) -> None:
        body = self._body(config.MAX_ADMIN_BODY_BYTES) if self.command == "POST" else {}
        status, reply = self.app.handle_admin(self.command, self.path, body)
        self._reply(status, reply)

    do_GET = do_POST = do_DELETE = _handle


class _Draining:
    # Non-daemon request threads + block_on_close: server_close() waits for
    # every in-flight request, so a drain never orphans a scraper command.
    daemon_threads = False
    block_on_close = True


class TCPServer(_Draining, ThreadingHTTPServer):
    pass


class UnixServer(_Draining, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    pass


def make_server(sock: socket.socket, handler: type[_Handler], app: Broker):
    handler_cls = type(handler.__name__, (handler,), {"app": app})
    cls = UnixServer if sock.family == socket.AF_UNIX else TCPServer
    srv = cls(sock.getsockname() if sock.family != socket.AF_UNIX else "",
              handler_cls, bind_and_activate=False)
    srv.socket.close()
    srv.socket = sock
    srv.server_address = sock.getsockname()
    return srv


def inherited_sockets() -> dict[str, socket.socket]:
    """sd_listen_fds(): fds from 3, named by $LISTEN_FDNAMES, for this PID only."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return {}
    try:
        n = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return {}
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    out = {}
    for i in range(n):
        name = names[i] if i < len(names) and names[i] else f"fd{3 + i}"
        out[name] = socket.socket(fileno=3 + i)
    for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(var, None)
    return out


def _dev_sockets() -> dict[str, socket.socket]:
    """Without systemd (local runs): bind the same addresses ourselves."""
    vm = socket.create_server((config.VM_HOST, config.VM_PORT))
    path = os.environ.get("RESEARCH_BROKER_ADMIN_SOCKET", config.ADMIN_SOCKET)
    try:
        os.unlink(path)
    except OSError:
        pass
    admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        admin.bind(path)
    finally:
        os.umask(old)
    admin.listen(16)
    return {config.FD_NAME_VM: vm, config.FD_NAME_ADMIN: admin}


def serve(app: Broker, socks: dict[str, socket.socket]) -> int:
    servers = [make_server(socks[config.FD_NAME_VM], VMHandler, app),
               make_server(socks[config.FD_NAME_ADMIN], AdminHandler, app)]
    threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.5},
                                daemon=True) for s in servers]
    for t in threads:
        t.start()

    def _term(signum, frame):
        log(f"signal {signum}: draining")
        app.exit_requested.set()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    # exit_requested: SIGTERM/SIGINT, or an idle code reload (registration).
    while not app.exit_requested.wait(config.SWEEP_INTERVAL_S):
        try:
            app.sweep()
        except Exception as e:  # never let the sweeper kill the broker
            log(f"sweep failed: {type(e).__name__}")
    for s in servers:
        s.shutdown()          # stop accepting; systemd queues new connections
    for s in servers:
        s.server_close()      # joins in-flight request threads
    app.save_state()
    log("drained, exiting")
    return 0


def main() -> int:
    creds = upstream.load_credentials()
    configured = sorted(k for k, v in creds.items() if v)
    app = Broker(creds, state_dir=os.environ.get("STATE_DIRECTORY", "").split(":")[0] or None)
    app.load_state()
    socks = inherited_sockets() or _dev_sockets()
    missing = {config.FD_NAME_VM, config.FD_NAME_ADMIN} - set(socks)
    if missing:
        log(f"missing listener(s): {sorted(missing)} (got {sorted(socks)})")
        return 2
    log(f"start code={app.loaded_digest[:12]} credentials={configured}")
    return serve(app, socks)


if __name__ == "__main__":
    sys.exit(main())
