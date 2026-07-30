"""_run_agent retries on ssh transport failure (rc=255) and returns
non-255 results without retrying."""
from __future__ import annotations

import subprocess

import mcp_server.server as server


class _Result:
    def __init__(self, rc):
        self.returncode = rc
        self.stdout = ""
        self.stderr = ""


def _env(monkeypatch):
    monkeypatch.setenv("RESEARCH_SSH_HOST", "127.0.0.1")
    monkeypatch.setenv("RESEARCH_SSH_PORT", "2223")
    monkeypatch.setenv("RESEARCH_SSH_KEY", "/fake/key")
    monkeypatch.setattr(server, "_secrets", lambda: {"claude-token": "t"})


def test_rc255_retries_then_succeeds(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr(server, "_SSH_RETRIES", 2)
    waits = []
    monkeypatch.setattr(server, "_wait_for_sshd", lambda h, p, t: waits.append((h, p)) or True)
    seq = iter([255, 255, 0])
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Result(next(seq)))
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 0
    assert len(waits) == 2  # waited before each of the 2 retries


def test_rc255_exhausts_retries(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr(server, "_SSH_RETRIES", 2)
    monkeypatch.setattr(server, "_wait_for_sshd", lambda h, p, t: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Result(255))
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 255  # gave up after retries, surfaced the transport failure


def test_non255_does_not_retry(monkeypatch):
    _env(monkeypatch)
    monkeypatch.setattr(server, "_SSH_RETRIES", 2)

    def _boom(*a, **k):
        raise AssertionError("must not wait/retry on a non-255 rc")

    monkeypatch.setattr(server, "_wait_for_sshd", _boom)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (calls.append(1), _Result(1))[1])
    rc, _out = server._run_agent(prompt="x", report_id="0" * 32, depth="normal")
    assert rc == 1
    assert len(calls) == 1  # single dial, no retry


def _mock_sock(monkeypatch, banner: bytes):
    import socket

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _t):
            pass

        def recv(self, _n):
            return banner

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _Sock())


def test_wait_for_sshd_returns_true_on_ssh_banner(monkeypatch):
    _mock_sock(monkeypatch, b"SSH-2.0-OpenSSH_10.3\r\n")
    assert server._wait_for_sshd("127.0.0.1", 2223, 5) is True


def test_wait_for_sshd_false_on_bare_tcp_accept(monkeypatch):
    # qemu SLIRP hostfwd accepts the TCP connection even when guest sshd is
    # down — a bare accept with no SSH banner must NOT count as ready
    # (the 2026-07-30 false-positive that made the retry fire into a dead VM).
    _mock_sock(monkeypatch, b"")
    assert server._wait_for_sshd("127.0.0.1", 2223, 1) is False
