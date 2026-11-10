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

Lifecycle (docs/egress-broker.md §12.2):
  * SIGHUP (`systemctl reload`) first recomputes the code digest
    (broker/digest.py). Unchanged: a no-op, the same process keeps serving
    (no drain, no state write). Changed: the drain below.
  * SIGTERM always drains:
      1. persist the run registry to $STATE_DIRECTORY at once, before any
         waiting, so a SIGKILL at TimeoutStopSec leaves state at most one
         drain stale instead of gone;
      2. stop accepting at once (systemd keeps queueing on the held
         sockets, so nothing is refused);
      3. finish in-flight requests (never orphan a scraper command);
      4. persist again, then exit 0.
    The next start loads the runs, so a restart mid-run is invisible to
    the run.
  * The code-watch oneshot reloads on every path event without hashing
    anything; the comparison is ours, against the digest taken at boot.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Digest the tree BEFORE importing it: a pull landing between the two then
# leaves `code` older than the loaded modules, so the next SIGHUP reloads.
# The other order would let stale code pass as current.
from broker.digest import code_digest  # noqa: E402

BOOT_DIGEST = code_digest(_ROOT)

import json  # noqa: E402
import re  # noqa: E402
import select  # noqa: E402
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


class Broker:
    """Everything request handling needs; no sockets (tests drive it directly)."""

    def __init__(self, creds: dict[str, str], transport=upstream.curl_transport,
                 scraper: scraper_proxy.Scraper | None = None,
                 registry: Registry | None = None, state_dir: str | None = None,
                 code_root: str = _ROOT, loaded_digest: str | None = None,
                 sleep=time.sleep):
        self.creds = creds
        self.transport = transport
        self.scraper = scraper or scraper_proxy.Scraper()
        self.registry = registry or Registry()
        self.state_dir = state_dir
        self.code_root = code_root
        self.loaded_digest = loaded_digest or code_digest(code_root)
        self.sleep = sleep
        # Set once a terminal stop has begun (see `_successor_possible`): the
        # broker keeps serving the runs it has, and takes no new ones, so the
        # drain's wait for an empty registry cannot be extended indefinitely
        # by arrivals. Plain bool, written by the signal loop and read by
        # request threads: a torn read is impossible and a stale read costs
        # one extra registration.
        self.stopping = False
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

    def code_changed(self) -> bool:
        """SIGHUP's question: is the tree on disk not the code we loaded?"""
        try:
            return code_digest(self.code_root) != self.loaded_digest
        except Exception:  # unreadable tree: reload, the oneshot handles "gone"
            return True

    # --- admin listener ---------------------------------------------------------
    def handle_admin(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        if method == "GET" and path == "/admin/health":
            return 200, {"status": "ok", "active_runs": self.registry.active(),
                         "code": self.loaded_digest}
        if method == "POST" and path == "/admin/runs":
            return self._register(body)
        m = _ADMIN_RUN_PATH.match(path)
        if method == "DELETE" and m:
            return 200, {"status": "ok", "summaries": self.deregister(m.group(1))}
        return 404, {"status": "error", "error": "not found"}

    def _register(self, body: dict | None) -> tuple[int, dict]:
        # A terminal stop is under way: serve the runs already registered,
        # refuse new ones. Without this the drain's wait for an empty
        # registry could be held open indefinitely by fresh arrivals, and a
        # run admitted here would be orphaned seconds later anyway. The
        # caller sees a closed reason code and fails loudly, which during
        # code⁻¹ is correct — there is no broker to come back to.
        if self.stopping:
            return 503, {"status": "error", "error": "stopping"}
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
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, prefix=".runs.")  # 0600
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": STATE_VERSION, "runs": runs}, f)
            f.flush()
            os.fsync(f.fileno())
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
            # The handover file is consumed, not required. If the unlink fails the
            # only effect is that the next start re-reads it and drops everything
            # already expired, which is harmless.
            except OSError:  # arftl-allow: swallowed-exception
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

    def setup(self) -> None:
        super().setup()
        self.server.reading(self.connection)

    def _received(self) -> bool:
        """The whole request is in: from here it is in flight and the drain
        waits for it. False if the drain already cut this connection."""
        return self.server.received(self.connection)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.server.forget(self.connection)

    def log_message(self, format, *args):  # noqa: A002 — per-request line is ours
        pass


class VMHandler(_Handler):
    def _handle(self) -> None:
        t0 = time.monotonic()
        path = self.path.split("?", 1)[0]
        big = path.endswith("/act") or path == "/v1/scraper/intercept"
        body = self._body(config.MAX_BROWSER_BODY_BYTES if big else config.MAX_BODY_BYTES) \
            if self.command == "POST" else {}
        if not self._received():
            return
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
        if not self._received():
            return
        status, reply = self.app.handle_admin(self.command, self.path, body)
        self._reply(status, reply)

    do_GET = do_POST = do_DELETE = _handle


class _Draining:
    # Non-daemon request threads + block_on_close: server_close() waits for
    # every in-flight request, so a drain never orphans a scraper command.
    # "In flight" means fully received: a connection still sending its
    # request is tracked separately and cut by the drain (cut_unfinished),
    # or server_close() would wait on whoever opens a socket and goes quiet
    # (the 15 s read timeout) or trickles bytes (forever).
    daemon_threads = False
    block_on_close = True

    def __init__(self, *args, **kwargs):
        self._unfinished: set = set()
        self._cut: set = set()
        self._conn_lock = threading.Lock()
        self._cutting = False
        super().__init__(*args, **kwargs)


    def reading(self, conn) -> None:
        with self._conn_lock:
            if not self._cutting:
                self._unfinished.add(conn)
                return
            self._cut.add(conn)  # accepted just before the drain, started after
        _hang_up(conn)

    def received(self, conn) -> bool:
        with self._conn_lock:
            self._unfinished.discard(conn)
            return conn not in self._cut

    def forget(self, conn) -> None:
        with self._conn_lock:
            self._unfinished.discard(conn)
            self._cut.discard(conn)

    def unfinished(self) -> int:
        with self._conn_lock:
            return len(self._unfinished)

    def cut_unfinished(self) -> int:
        with self._conn_lock:
            self._cutting = True
            conns, self._unfinished = self._unfinished, set()
            self._cut |= conns
        for conn in conns:
            _hang_up(conn)
        return len(conns)


def _hang_up(conn) -> None:
    """Wake the handler blocked reading this connection (EOF); it then
    returns without dispatching, since received() says it was cut."""
    try:
        conn.shutdown(socket.SHUT_RDWR)
    # The point is to wake a blocked reader. A peer that has already gone away
    # raises ENOTCONN here, which IS the desired end state, so there is nothing
    # to report and nothing to retry.
    except OSError:  # arftl-allow: swallowed-exception
        pass


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
    # Clearing a stale socket path before bind. ENOENT is the normal case (nothing
    # there). A path that exists and cannot be removed surfaces immediately as the
    # bind() failure below, which is not swallowed, so this cannot hide a broken
    # listener.
    except OSError:  # arftl-allow: swallowed-exception
        pass
    admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        admin.bind(path)
    finally:
        os.umask(old)
    admin.listen(16)
    return {config.FD_NAME_VM: vm, config.FD_NAME_ADMIN: admin}


def _sweep_loop(app: Broker) -> None:
    """TTL sweeps, deliberately OFF the loop that reads the signal fd.

    A sweep deregisters every expired run, and each deregister closes that run's
    scraper sessions (`deregister` -> `close_all`) at up to
    `SCRAPER_TIMEOUT_S["close"]` = 135 s apiece against a hung scraper. Running that
    inline on the signal loop meant a SIGTERM arriving mid-sweep was not even READ
    for minutes: two stuck closes already exceed `TimeoutStopSec=210`, so the drain's
    "persist at once" (§12.2) never ran and systemd SIGKILLed the broker with no
    handover file — losing the registry the switchover window depends on. This is the
    same latency the wakeup fd above was introduced to kill; the sweep was a second
    door into it.

    `Registry` and every `Run` carry their own locks, and the admin routes already
    call `deregister` from the request threads, so moving the sweep here introduces
    no concurrency that did not already exist.
    """
    while True:
        time.sleep(config.SWEEP_INTERVAL_S)
        try:
            app.sweep()
        except Exception as e:  # never let the sweeper kill the broker
            log(f"sweep failed: {type(e).__name__}")


def serve(app: Broker, socks: dict[str, socket.socket]) -> int:
    # Signals reach the main loop through a wakeup fd: CPython's C handler
    # writes the signal number there from whichever thread the kernel chose.
    # A Python-level handler alone runs only when the MAIN thread next runs
    # bytecode, so a SIGTERM delivered to a request thread would wait out the
    # main thread's sleep (SWEEP_INTERVAL_S) before the drain even began.
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    signal.set_wakeup_fd(wake_w, warn_on_full_buffer=False)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda signum, frame: None)  # the fd carries it

    servers = [make_server(socks[config.FD_NAME_VM], VMHandler, app),
               make_server(socks[config.FD_NAME_ADMIN], AdminHandler, app)]
    threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.5},
                                daemon=True) for s in servers]
    for t in threads:
        t.start()
    threading.Thread(target=_sweep_loop, args=(app,), daemon=True).start()

    while True:
        # Nothing but signals here. The timeout only bounds how long select blocks;
        # a wake with no signal pending just loops (see _sweep_loop for why no work
        # may run on this loop).
        if not select.select([wake_r], [], [], config.SWEEP_INTERVAL_S)[0]:
            continue
        try:
            got = set(os.read(wake_r, 64))
        except BlockingIOError:
            continue
        stop = sorted(got & {signal.SIGTERM, signal.SIGINT})
        if stop:
            log(f"signal {stop[0]}: draining")
            break
        if signal.SIGHUP in got:
            # `systemctl reload` on every code-path event (§12.2 step 4).
            if app.code_changed():
                log(f"signal {signal.SIGHUP}: code changed, draining for reload")
                break
            log(f"signal {signal.SIGHUP}: code unchanged "
                f"({app.loaded_digest[:12]}), still serving")
    # A terminal stop — code⁻¹ removed `broker/`, so no successor process can
    # load the state we are about to save — must wait for the RUNS, not just
    # the requests. A registered run is idle between calls, so an empty
    # request queue means nothing about whether it still needs us, and
    # everything below stops serving. Measured in b16's T6b: the drain
    # finished in 4.9 s, saved 2 runs and exited with ~55 s of a browse
    # session left, and every later call got `broker unavailable (infra)`.
    # Keep accepting for the runs we already have; `app.stopping` refuses new
    # registrations so arrivals cannot hold this open.
    if not _successor_possible(app):
        app.stopping = True
        deadline = time.monotonic() + config.DRAIN_RUNS_BUDGET_S
        left = app.registry.active()
        if left:
            log(f"terminal stop: serving {left} registered run(s) out, "
                f"up to {config.DRAIN_RUNS_BUDGET_S:.0f}s")
        while left and time.monotonic() < deadline:
            time.sleep(0.2)
            left = app.registry.active()
        # Loud either way: a drop here is the one case §12.6's gate exists to
        # prevent, so it must never be inferable only from a later error.
        log(f"terminal stop: {'runs drained' if not left else f'DROPPING {left} run(s)'}"
            f" after {config.DRAIN_RUNS_BUDGET_S - max(deadline - time.monotonic(), 0):.1f}s")
    # Persist first: everything below can outlast TimeoutStopSec, and a
    # SIGKILL then must cost at most the drain's progress, not the registry.
    _save(app)
    for s in servers:
        s.shutdown()          # stop accepting at once; systemd queues new connections
    # Requests still arriving get a short grace, then are cut; only fully
    # received requests are in flight and worth the join below.
    deadline = time.monotonic() + config.DRAIN_READ_GRACE_S
    while any(s.unfinished() for s in servers) and time.monotonic() < deadline:
        time.sleep(0.05)
    cut = sum(s.cut_unfinished() for s in servers)
    if cut:
        log(f"drain: cut {cut} connection(s) that never finished their request")
    for s in servers:
        s.server_close()      # joins in-flight request threads (bounded by route timeouts)
    _save(app)                # the handover includes work finished during the drain
    log("drained, exiting")
    return 0


def _save(app: Broker) -> None:
    try:
        app.save_state()
    except OSError as e:  # a full disk must not stop the drain
        log(f"state save failed: {type(e).__name__}")


def _successor_possible(app: Broker) -> bool:
    """Can another broker process come back and load the state we save?

    This is the question that decides whether a drain may exit on an empty
    request queue. On a reload or a restart the answer is yes: the state file
    is a handover, the sockets stay activated, and a run's next call is
    queued by systemd for the successor to serve — so waiting for runs would
    only delay the new code for no gain.

    On code⁻¹ the answer is no. The oneshot stops the sockets *and* the
    service because `broker/server.py` is gone from the checkout, so the
    saved state has no reader and every registered run is orphaned the
    moment this process exits.

    Read the entry module itself rather than the tree digest: `code_changed`
    already treats an unreadable tree as "reload" and cannot distinguish
    changed from deleted, which is precisely the distinction that matters
    here. A missing file is unambiguous; any other error means the file is
    there and something else is wrong, so assume a successor and keep the
    fast path.
    """
    try:
        return os.path.exists(os.path.join(app.code_root, "broker", "server.py"))
    except OSError:
        return True


def main() -> int:
    creds = upstream.load_credentials()
    configured = sorted(k for k, v in creds.items() if v)
    app = Broker(creds, state_dir=os.environ.get("STATE_DIRECTORY", "").split(":")[0] or None,
                 loaded_digest=BOOT_DIGEST)
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
