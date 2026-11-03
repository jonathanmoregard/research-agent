"""The real broker process: socket activation, SIGTERM drain, restart.

Runs broker/server.py exactly as systemd does (`python3 -I -B server.py`,
listeners inherited as fds 3.. named by $LISTEN_FDNAMES, keys from
$CREDENTIALS_DIRECTORY, state in $STATE_DIRECTORY) and checks:
  * fds are mapped by name, not order (admin first, as systemd sends them);
  * SIGTERM finishes an in-flight scraper call before exiting 0;
  * a connection made while the old process drains is served by the next;
  * the next process loads the runs, so the old token keeps working.
Hermetic: the scraper is a local stub; no keyed route is called.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RUN_ID = "c" * 32

LAUNCHER = r"""
import fcntl, os, sys
vm, admin = int(os.environ.pop("T_VM_FD")), int(os.environ.pop("T_ADMIN_FD"))
# Park both above 4 first: a plain dup() takes the lowest free fd, which is
# 3, and the dup2 onto 3 below would then clobber the parked vm listener.
hi_vm = fcntl.fcntl(vm, fcntl.F_DUPFD, 10)
hi_admin = fcntl.fcntl(admin, fcntl.F_DUPFD, 10)
os.dup2(hi_admin, 3); os.dup2(hi_vm, 4)
for fd in (vm, admin, hi_vm, hi_admin):
    if fd not in (3, 4):
        os.close(fd)
os.set_inheritable(3, True); os.set_inheritable(4, True)
os.environ["LISTEN_PID"] = str(os.getpid())
os.environ["LISTEN_FDS"] = "2"
os.environ["LISTEN_FDNAMES"] = "admin:vm"
os.execv(sys.executable, [sys.executable, "-I", "-B", sys.argv[1]])
"""


class SlowScraper(http.server.ThreadingHTTPServer):
    def __init__(self, delay):
        self.hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(h):
                n = int(h.headers.get("Content-Length", "0"))
                body = json.loads(h.rfile.read(n))
                self.hits.append(body["url"])
                time.sleep(delay)
                url = body["url"]
                data = json.dumps({"status": "ok", "requested_url": url, "final_url": url,
                                   "http_status": 200, "title": "t", "html": "", "text": "",
                                   "links": ["https://next.example/page"]}).encode()
                h.send_response(200)
                h.send_header("Content-Length", str(len(data)))
                h.end_headers()
                h.wfile.write(data)

            def log_message(h, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()


def _unix(path):
    class C(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)
    return C("localhost", timeout=20)


class Rig:
    """A copy of the broker code wired to a stub scraper, plus the two
    listeners systemd would hold. `start()` is one socket activation."""

    def __init__(self, tmp_path, delay):
        self.scraper = SlowScraper(delay=delay)
        # The broker reads its scraper base from config; point a copy of the
        # code at the stub (config is code, not env, by design).
        self.code = code = tmp_path / "rb"
        (code / "broker").mkdir(parents=True)
        (code / "scraper").mkdir()
        for f in (REPO / "broker").glob("*.py"):
            text = f.read_text()
            if f.name == "config.py":
                text = text.replace('SCRAPER_BASE = "http://127.0.0.1:8123"',
                                    f'SCRAPER_BASE = "http://127.0.0.1:{self.scraper.server_port}"')
                text = text.replace('SCRAPER_TOKEN_FILE = "/var/lib/scraper-bearer/token"',
                                    f'SCRAPER_TOKEN_FILE = "{tmp_path / "bearer"}"')
            (code / "broker" / f.name).write_text(text)
        (code / "scraper" / "urlpolicy.py").write_text(
            (REPO / "scraper" / "urlpolicy.py").read_text())
        (tmp_path / "bearer").write_text("bearer\n")
        self.creds = tmp_path / "creds"
        self.creds.mkdir()
        (self.creds / "exa-api-key").write_text("FAKE-exa-KEY\n")
        self.state = tmp_path / "state"
        self.state.mkdir()
        self.vm = socket.create_server(("127.0.0.1", 0), backlog=16)
        self.admin_path = str(tmp_path / "admin.sock")
        self.admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.admin.bind(self.admin_path)
        self.admin.listen(16)
        self.port = self.vm.getsockname()[1]
        self.procs = []

    def start(self):
        env = {"PATH": os.environ.get("PATH", ""), "CREDENTIALS_DIRECTORY": str(self.creds),
               "STATE_DIRECTORY": str(self.state), "T_VM_FD": str(self.vm.fileno()),
               "T_ADMIN_FD": str(self.admin.fileno())}
        p = subprocess.Popen(
            [sys.executable, "-c", LAUNCHER, str(self.code / "broker" / "server.py")],
            env=env, pass_fds=(self.vm.fileno(), self.admin.fileno()),
            stderr=subprocess.PIPE, text=True)
        self.procs.append(p)
        return p

    def admin_call(self, method, path, body=None):
        c = _unix(self.admin_path)
        c.request(method, path, json.dumps(body) if body is not None else None,
                  {"Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def register(self):
        status, reply = self.admin_call("POST", "/admin/runs", {
            "run_id": RUN_ID, "depth": "normal", "provider": "claude",
            "prompt_urls": ["https://start.example/"], "ttl_s": 600})
        assert status == 200, reply
        return reply["token"]

    def post(self, path, body, token):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        c.request("POST", path, json.dumps(body), {"Authorization": f"Bearer {token}",
                                                   "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def wait_for_hit(self, alive):
        deadline = time.monotonic() + 10
        while not self.scraper.hits and time.monotonic() < deadline and alive():
            time.sleep(0.02)
        assert self.scraper.hits

    def close(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait(5)
        self.scraper.shutdown()


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path, delay=1.5)
    yield r
    r.close()


def test_socket_activation_drain_and_restart(rig):
    state = rig.state
    p1 = rig.start()
    token = rig.register()

    results = {}
    t = threading.Thread(target=lambda: results.update(
        first=rig.post("/v1/scraper/render", {"url": "https://start.example/"}, token)))
    t.start()
    rig.wait_for_hit(t.is_alive)
    p1.send_signal(signal.SIGTERM)  # mid-flight
    time.sleep(0.2)
    # Made during the drain: queues on the held socket.
    t2 = threading.Thread(target=lambda: results.update(
        queued=rig.post("/v1/scraper/render", {"url": "https://next.example/page"}, token)))
    t2.start()
    t.join(10)
    assert results["first"][0] == 200, results
    assert p1.wait(10) == 0
    err1 = p1.stderr.read()
    assert "draining" in err1 and "state saved: 1 run(s)" in err1, err1
    assert (state / "runs.json").exists()

    p2 = rig.start()  # what socket activation does on the queued connection
    t2.join(15)
    # Served by the new process, with the ledger from the old one
    # (next.example/page came from the first render's links[]).
    assert results["queued"][0] == 200, results
    p2.send_signal(signal.SIGTERM)
    assert p2.wait(10) == 0
    assert "state loaded: 1 run(s)" in p2.stderr.read()
    assert "FAKE-exa-KEY" not in err1


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_drain_persists_before_joining_in_flight(tmp_path, sig):
    """§12.2: the registry hits disk the moment the drain starts, not after
    the in-flight join. systemd SIGKILLs at TimeoutStopSec; a kill while a
    165 s act is still running must leave runs.json behind, so the next
    process still knows the run's token."""
    rig = Rig(tmp_path, delay=8)  # in flight far longer than this test waits
    try:
        p1 = rig.start()
        token = rig.register()
        outcome = {}

        def in_flight():
            try:
                outcome["reply"] = rig.post(
                    "/v1/scraper/render", {"url": "https://start.example/"}, token)
            except (http.client.HTTPException, OSError) as e:
                outcome["reply"] = e  # killed mid-request, as at TimeoutStopSec

        t = threading.Thread(target=in_flight, daemon=True)
        t.start()
        rig.wait_for_hit(t.is_alive)
        p1.send_signal(sig)
        saved = rig.state / "runs.json"
        deadline = time.monotonic() + 3
        while not saved.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert t.is_alive(), "the in-flight request must still be running"
        assert saved.exists(), "drain must persist before it waits for in-flight requests"
        p1.kill()  # what TimeoutStopSec does
        p1.wait(5)
        t.join(5)
        assert isinstance(outcome["reply"], (http.client.HTTPException, OSError)), outcome
        runs = json.loads(saved.read_text())["runs"]
        assert [r["run_id"] for r in runs] == [RUN_ID]

        p2 = rig.start()
        rig.scraper.hits.clear()
        status, reply = rig.post("/v1/scraper/render", {"url": "https://start.example/"}, token)
        # Not 401 "run not registered": the token survived the kill.
        assert status != 401, reply
        assert rig.scraper.hits == ["https://start.example/"]
        t_sig = time.monotonic()
        p2.send_signal(signal.SIGTERM)
        try:
            p2.wait(20)
        except subprocess.TimeoutExpired:  # seen once in ~55 runs; keep the evidence
            p2.kill()
            p2.wait(5)
            raise AssertionError(f"drain stuck {time.monotonic() - t_sig:.1f}s after "
                                 f"SIGTERM; broker stderr: {p2.stderr.read()!r}") from None
        assert p2.returncode == 0
    finally:
        rig.close()


def test_admin_health_reports_location_independent_code_hash(rig, tmp_path):
    """The code-watch oneshot (§12.2 step 4) compares its own tree hash of
    broker/ + scraper/urlpolicy.py with this field. The broker runs from
    /run/rb, the oneshot hashes the checkout: the hash must not depend on
    where the tree is mounted."""
    sys.path.insert(0, str(REPO))
    try:
        from broker.digest import code_digest
    finally:
        sys.path.remove(str(REPO))
    p = rig.start()
    status, reply = rig.admin_call("GET", "/admin/health")
    assert status == 200
    assert reply["code"] == code_digest(str(rig.code))
    # The oneshot's call, exactly (§12.2 step 4): one implementation, run
    # from the checkout root, printing what the broker reports.
    cli = subprocess.run([sys.executable, "-m", "broker.digest"], cwd=rig.code,
                         capture_output=True, text=True, timeout=30)
    assert cli.returncode == 0, cli.stderr
    assert cli.stdout.strip() == reply["code"]
    # The same tree mounted elsewhere hashes the same.
    copy = tmp_path / "elsewhere"
    (copy / "broker").mkdir(parents=True)
    (copy / "scraper").mkdir()
    for f in (REPO / "broker").glob("*.py"):
        (copy / "broker" / f.name).write_bytes(f.read_bytes())
    (copy / "scraper" / "urlpolicy.py").write_bytes((REPO / "scraper" / "urlpolicy.py").read_bytes())
    assert code_digest(str(copy)) == code_digest(str(REPO))
    p.send_signal(signal.SIGTERM)
    assert p.wait(10) == 0
