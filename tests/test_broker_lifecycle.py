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

REPO = Path(__file__).resolve().parent.parent
RUN_ID = "c" * 32

LAUNCHER = r"""
import os, sys
vm, admin = int(os.environ.pop("T_VM_FD")), int(os.environ.pop("T_ADMIN_FD"))
hi_vm, hi_admin = os.dup(vm), os.dup(admin)
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


def test_socket_activation_drain_and_restart(tmp_path, monkeypatch):
    scraper = SlowScraper(delay=1.5)
    # The broker reads its scraper base from config; point a copy of the
    # code at the stub (config is code, not env, by design).
    code = tmp_path / "rb"
    (code / "broker").mkdir(parents=True)
    (code / "scraper").mkdir()
    for f in (REPO / "broker").glob("*.py"):
        text = f.read_text()
        if f.name == "config.py":
            text = text.replace('SCRAPER_BASE = "http://127.0.0.1:8123"',
                                f'SCRAPER_BASE = "http://127.0.0.1:{scraper.server_port}"')
            text = text.replace('SCRAPER_TOKEN_FILE = "/var/lib/scraper-bearer/token"',
                                f'SCRAPER_TOKEN_FILE = "{tmp_path / "bearer"}"')
        (code / "broker" / f.name).write_text(text)
    (code / "scraper" / "urlpolicy.py").write_text((REPO / "scraper" / "urlpolicy.py").read_text())
    (tmp_path / "bearer").write_text("bearer\n")
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "exa-api-key").write_text("FAKE-exa-KEY\n")
    state = tmp_path / "state"
    state.mkdir()

    vm = socket.create_server(("127.0.0.1", 0), backlog=16)
    admin_path = str(tmp_path / "admin.sock")
    admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    admin.bind(admin_path)
    admin.listen(16)
    port = vm.getsockname()[1]

    def start():
        env = {"PATH": os.environ.get("PATH", ""), "CREDENTIALS_DIRECTORY": str(creds),
               "STATE_DIRECTORY": str(state), "T_VM_FD": str(vm.fileno()),
               "T_ADMIN_FD": str(admin.fileno())}
        return subprocess.Popen([sys.executable, "-c", LAUNCHER, str(code / "broker" / "server.py")],
                                env=env, pass_fds=(vm.fileno(), admin.fileno()),
                                stderr=subprocess.PIPE, text=True)

    def post(path, body, token):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        c.request("POST", path, json.dumps(body), {"Authorization": f"Bearer {token}",
                                                   "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    p1 = start()
    try:
        c = _unix(admin_path)
        c.request("POST", "/admin/runs", json.dumps({
            "run_id": RUN_ID, "depth": "normal", "provider": "claude",
            "prompt_urls": ["https://start.example/"], "ttl_s": 600}),
            {"Content-Type": "application/json"})
        r = c.getresponse()
        reply = json.loads(r.read())
        assert r.status == 200, reply
        token = reply["token"]

        results = {}
        t = threading.Thread(target=lambda: results.update(
            first=post("/v1/scraper/render", {"url": "https://start.example/"}, token)))
        t.start()
        deadline = time.monotonic() + 10
        while not scraper.hits and time.monotonic() < deadline and t.is_alive():
            time.sleep(0.02)
        assert scraper.hits, (results, p1.poll())
        p1.send_signal(signal.SIGTERM)  # mid-flight
        time.sleep(0.2)
        # Made during the drain: queues on the held socket.
        t2 = threading.Thread(target=lambda: results.update(
            queued=post("/v1/scraper/render", {"url": "https://next.example/page"}, token)))
        t2.start()
        t.join(10)
        assert results["first"][0] == 200, results
        assert p1.wait(10) == 0
        err1 = p1.stderr.read()
        assert "draining" in err1 and "state saved: 1 run(s)" in err1, err1
        assert (state / "runs.json").exists()

        p2 = start()  # what socket activation does on the queued connection
        t2.join(15)
        # Served by the new process, with the ledger from the old one
        # (next.example/page came from the first render's links[]).
        assert results["queued"][0] == 200, results
        p2.send_signal(signal.SIGTERM)
        assert p2.wait(10) == 0
        assert "state loaded: 1 run(s)" in p2.stderr.read()
        assert "FAKE-exa-KEY" not in err1
    finally:
        for p in (p1, locals().get("p2")):
            if p is not None and p.poll() is None:
                p.kill()
        scraper.shutdown()
