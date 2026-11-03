"""§12.4 dual-mode dispatch in mcp_server.server._dial_agent.

Every dial picks a protocol from two deploy-state facts, era first:
  /etc/research-agent/egress-era   absent | legacy-ok | broker-only | other
  admin socket + scripts/.guest-protocol == broker-v1

and the security claims pinned here are:
  * `broker-only` never ships keys, whatever the socket's state;
  * an unrecognised era fails closed;
  * the legacy branch reads keys from os.environ ONLY — never the GNOME
    keyring, which `_secret()` falls back to and nixos-B cannot clear by
    dropping the wrapper's exports alone;
  * registration retries a socket that is briefly absent or refusing (a
    reload window), instead of failing the call.

Hermetic: ssh is a fake subprocess.run, the broker is an in-process
AF_UNIX stub, the keyring is a patched function.
"""
from __future__ import annotations

import http.server
import json
import logging
import os
import shlex
import socket
import socketserver
import subprocess
import threading
import time
from unittest.mock import MagicMock

import pytest

from mcp_server import server

REPORT_ID = "ab" * 16
KEY_ENV = {
    "EXA_API_KEY": "CANARY-exa",
    "TAVILY_API_KEY": "CANARY-tavily",
    "EUIPO_CLIENT_ID": "CANARY-euipo-id",
    "EUIPO_CLIENT_SECRET": "CANARY-euipo-secret",
    "EBAY_CLIENT_ID": "CANARY-ebay-id",
    "EBAY_CLIENT_SECRET": "CANARY-ebay-secret",
    "TRADERA_APP_ID": "CANARY-tradera-id",
    "TRADERA_APP_KEY": "CANARY-tradera-key",
}
KEYED_NAMES = set(server._SECRET_ENV) - {"claude-token"}


class StubBroker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """The broker's admin API, recording every request."""

    daemon_threads = True

    def __init__(self, path, *, status=200, delay=0.0, bind_and_activate=True):
        self.requests = []
        self.status = status
        self.delay = delay
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def _do(h):
                n = int(h.headers.get("Content-Length", "0") or 0)
                body = json.loads(h.rfile.read(n)) if n else None
                outer.requests.append((h.command, h.path, body))
                time.sleep(outer.delay)
                reply = {"status": "ok"}
                if h.command == "POST":
                    reply["token"] = f"TOKEN-{len(outer.requests)}"
                data = json.dumps(reply).encode()
                h.send_response(outer.status)
                h.send_header("Content-Length", str(len(data)))
                h.end_headers()
                h.wfile.write(data)

            do_POST = do_DELETE = do_GET = _do

            def log_message(h, *a):
                pass

        super().__init__(path, H, bind_and_activate=bind_and_activate)

    def serve(self):
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()
        return self


class Dial:
    def __init__(self, tmp_path, monkeypatch, caplog):
        self.tmp = tmp_path
        self.era = tmp_path / "egress-era"
        self.marker = tmp_path / ".guest-protocol"
        self.admin = str(tmp_path / "admin.sock")
        self.calls = []
        self.keyring_calls = []
        self.caplog = caplog
        monkeypatch.setattr(server, "_EGRESS_ERA_PATH", self.era)
        monkeypatch.setattr(server, "_GUEST_PROTOCOL_PATH", self.marker)
        monkeypatch.setenv("RESEARCH_BROKER_ADMIN", self.admin)
        monkeypatch.setattr(server, "_BROKER_REGISTER_BUDGET_S", 2.0)
        monkeypatch.setattr(server, "_BROKER_CONNECT_RETRY_S", 0.5)
        for k, v in {"RESEARCH_SSH_HOST": "127.0.0.1", "RESEARCH_SSH_PORT": "2223",
                     "RESEARCH_SSH_KEY": "/fake/key", "RESEARCH_SSH_USER": "agent",
                     "RESEARCH_SSH_KNOWN_HOSTS": str(tmp_path / "ssh" / "known_hosts"),
                     "CLAUDE_CODE_OAUTH_TOKEN": "CANARY-claude", **KEY_ENV}.items():
            monkeypatch.setenv(k, v)
        nowhere = server.Path("/dev/null/does-not-exist-for-tests")
        monkeypatch.setattr(server, "_CLAUDE_CREDENTIALS_PATH", nowhere)
        monkeypatch.setattr(server, "_CODEX_AUTH_PATH", nowhere)

        def keyring(key):
            self.keyring_calls.append(key)
            return f"KEYRING-{key}"

        monkeypatch.setattr(server, "_keyring_lookup", keyring)
        server.SECRETS_CACHE.clear()

        def fake_run(argv, **kw):
            self.calls.append((argv, kw.get("input")))
            return MagicMock(returncode=self.rc.pop(0) if self.rc else 0,
                             stdout="DONE\n", stderr="")

        self.rc = []
        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(server, "_wait_for_sshd", lambda *a, **k: None)
        caplog.set_level(logging.INFO, logger="research-agent")

    def broker(self, **kw):
        return StubBroker(self.admin, **kw).serve()

    def run(self, prompt="look at https://shop.example/item and tell me"):
        return server._dial_agent(prompt, REPORT_ID, "normal")

    def fields(self, i=-1):
        return self.calls[i][1].split("\0")[:-1]

    def mode_line(self):
        lines = [r.getMessage() for r in self.caplog.records if " mode=" in r.getMessage()]
        assert len(lines) == 1, lines
        return lines[0]


@pytest.fixture
def dial(tmp_path, monkeypatch, caplog):
    d = Dial(tmp_path, monkeypatch, caplog)
    yield d
    server.SECRETS_CACHE.clear()


# --- transition era: legacy -------------------------------------------------------

def test_no_era_no_socket_is_todays_legacy_dial(dial):
    rc, _ = dial.run()
    assert rc == 0
    fields = dial.fields()
    assert len(fields) == 11
    assert fields[0] == "CANARY-claude"
    assert fields[2:10] == list(KEY_ENV.values())
    assert shlex.quote(server._GUEST_SCRIPT_LEGACY) in dial.calls[0][0][-1]
    assert "mode=legacy reason=no-broker era=absent" in dial.mode_line()


def test_legacy_ok_without_protocol_marker_is_legacy(dial):
    """A reverted checkout under a new in-memory server: socket up, marker gone."""
    dial.era.write_text("legacy-ok\n")
    b = dial.broker()
    try:
        dial.run()
    finally:
        b.shutdown()
    assert len(dial.fields()) == 11
    assert b.requests == []
    assert "mode=legacy reason=no-protocol-marker era=legacy-ok" in dial.mode_line()


def test_legacy_resolver_never_consults_the_keyring(dial, monkeypatch):
    """After nixos-B drops the wrapper's exports, _secret() would still find
    exa/tavily in the keyring. The legacy branch must not: env or nothing."""
    for name in KEY_ENV:
        if name != "EXA_API_KEY":
            monkeypatch.delenv(name)
    dial.run()
    fields = dial.fields()
    assert fields[2] == "CANARY-exa"
    assert fields[3:10] == [""] * 7
    assert not any(f.startswith("KEYRING-") for f in fields)
    assert dial.keyring_calls == []


def test_legacy_without_any_key_in_env_fails_closed(dial, monkeypatch):
    """Legacy permitted but no keys in env → fail closed, even though the
    keyring would answer for every one of them."""
    for name in KEY_ENV:
        monkeypatch.delenv(name)
    with pytest.raises(server._BrokerUnavailable):
        dial.run()
    assert dial.calls == []
    assert dial.keyring_calls == []


# --- broker mode ------------------------------------------------------------------

def test_broker_mode_registers_ships_token_not_keys_and_deregisters(dial):
    dial.era.write_text("legacy-ok\n")
    dial.marker.write_text("broker-v1\n")
    b = dial.broker()
    try:
        rc, _ = dial.run()
    finally:
        b.shutdown()
    assert rc == 0
    fields = dial.fields()
    assert fields[0] == "broker-v1"
    assert len(fields) == 5  # version + claude token, codex auth, broker token, prompt
    assert fields[1] == "CANARY-claude" and fields[2] == "" and fields[3] == "TOKEN-1"
    payload = dial.calls[0][1]
    assert not any(v in payload for v in KEY_ENV.values())
    assert shlex.quote(server._GUEST_SCRIPT_BROKER) in dial.calls[0][0][-1]
    (m1, p1, reg), (m2, p2, _) = b.requests
    assert (m1, p1) == ("POST", "/admin/runs")
    assert reg == {"run_id": REPORT_ID, "depth": "normal", "provider": "claude",
                   "prompt_urls": ["https://shop.example/item"],
                   "ttl_s": server.AGENT_TIMEOUT + 300}
    assert (m2, p2) == ("DELETE", f"/admin/runs/{REPORT_ID}")
    assert "mode=broker reason=broker-present era=legacy-ok" in dial.mode_line()
    assert dial.keyring_calls == []


def test_broker_mode_prompt_urls_come_from_the_user_prompt_only(dial):
    """The template is formatted AFTER extraction: template text never seeds
    the ledger."""
    dial.marker.write_text("broker-v1\n")
    b = dial.broker()
    try:
        dial.run(prompt="no links here")
    finally:
        b.shutdown()
    assert b.requests[0][2]["prompt_urls"] == []


def test_each_ssh_attempt_gets_its_own_registration(dial):
    """§2.4: register per attempt, deregister in that attempt's finally."""
    dial.marker.write_text("broker-v1\n")
    dial.rc = [255, 0]
    b = dial.broker()
    try:
        rc, _ = dial.run()
    finally:
        b.shutdown()
    assert rc == 0
    assert [(m, p) for m, p, _ in b.requests] == [
        ("POST", "/admin/runs"), ("DELETE", f"/admin/runs/{REPORT_ID}"),
        ("POST", "/admin/runs"), ("DELETE", f"/admin/runs/{REPORT_ID}")]
    assert [dial.fields(i)[3] for i in (0, 1)] == ["TOKEN-1", "TOKEN-3"]


def test_registration_failure_in_transition_era_fails_closed(dial):
    """Socket present but registration fails → closed, never legacy."""
    dial.marker.write_text("broker-v1\n")
    b = dial.broker(status=500)
    try:
        with pytest.raises(server._BrokerUnavailable):
            dial.run()
    finally:
        b.shutdown()
    assert dial.calls == []


# --- broker-only era --------------------------------------------------------------

def test_broker_only_with_socket_absent_fails_closed_reading_no_key(dial, monkeypatch):
    dial.era.write_text("broker-only\n")
    dial.marker.write_text("broker-v1\n")
    read = []

    class Env(dict):
        def get(self, k, default=None):
            read.append(k)
            return super().get(k, default)

        def __getitem__(self, k):
            read.append(k)
            return super().__getitem__(k)

    monkeypatch.setattr(os, "environ", Env(os.environ))
    # A long read budget must not matter: no socket is no reload (§2.6).
    monkeypatch.setattr(server, "_BROKER_REGISTER_BUDGET_S", 30.0)
    t0 = time.monotonic()
    with pytest.raises(server._BrokerUnavailable):
        dial.run()
    assert time.monotonic() - t0 < 3, "the era's verdict after the short retry only"
    assert dial.calls == [], "no ssh dial"
    assert dial.keyring_calls == []
    assert not set(read) & set(KEY_ENV), f"keyed env read on the closed path: {read}"
    assert "mode=closed reason=broker-absent era=broker-only" in dial.mode_line()


def test_broker_only_rides_out_a_socket_unit_restart(dial):
    """The socket path reappears within the short retry: broker mode, no error."""
    dial.era.write_text("broker-only\n")
    dial.marker.write_text("broker-v1\n")
    b = StubBroker(dial.admin, bind_and_activate=False)

    def bring_up():
        time.sleep(0.2)
        b.server_bind()
        b.server_activate()
        b.serve()

    t = threading.Thread(target=bring_up, daemon=True)
    t.start()
    try:
        rc, _ = dial.run()
    finally:
        t.join(5)
        b.shutdown()
    assert rc == 0 and dial.fields()[0] == "broker-v1"
    assert "mode=broker" in dial.mode_line()


def test_broker_only_without_protocol_marker_fails_closed(dial):
    """code⁻¹ before B⁻¹: the designed loud failure, not a legacy fallback."""
    dial.era.write_text("broker-only\n")
    b = dial.broker()
    try:
        with pytest.raises(server._BrokerUnavailable):
            dial.run()
    finally:
        b.shutdown()
    assert dial.calls == [] and b.requests == []
    assert "mode=closed reason=no-protocol-marker era=broker-only" in dial.mode_line()


def test_broker_only_with_broker_up_is_broker_mode(dial):
    dial.era.write_text("broker-only\n")
    dial.marker.write_text("broker-v1\n")
    b = dial.broker()
    try:
        dial.run()
    finally:
        b.shutdown()
    assert dial.fields()[0] == "broker-v1"
    assert "mode=broker" in dial.mode_line()


@pytest.mark.parametrize("value", ["legacy", "", "broker-only legacy-ok", "LEGACY-OK"])
def test_unrecognised_era_fails_closed(dial, value):
    dial.era.write_text(value)
    with pytest.raises(server._BrokerUnavailable):
        dial.run()
    assert dial.calls == [] and dial.keyring_calls == []
    assert "mode=closed reason=era-unrecognised era=unrecognised" in dial.mode_line()


def test_research_reports_broker_unavailable(dial, monkeypatch, tmp_path):
    """The fail-closed exception surfaces as a readable infra error."""
    dial.era.write_text("broker-only\n")
    monkeypatch.setattr(server, "REPORTS_DIR", tmp_path)

    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(server, "_vm_lock", lambda *a, **k: _Lock())
    monkeypatch.setattr(server, "_scanner_health_gate", lambda: (True, ""))
    out = server.research("a question", depth="normal")
    assert out["status"] == "error" and out["error"] == "research-broker unavailable"
    assert not list(tmp_path.glob("*.md"))


# --- the registration client ------------------------------------------------------

def test_registration_budgets_split_by_phase():
    """§2.6: a reload never fails connect() (systemd holds the listener), so
    the long budget belongs to the read; ENOENT/ECONNREFUSED mean the socket
    unit is not running and get a short retry only."""
    assert server._BROKER_REGISTER_BUDGET_S >= 240  # drain 210 s + start
    assert server._BROKER_CONNECT_RETRY_S <= 30
    assert server._BROKER_DEREGISTER_TIMEOUT_S <= 10


def test_slow_reply_is_the_reload_window_and_gets_the_read_budget(dial, monkeypatch):
    """Connected, then the reply takes longer than the whole connect retry:
    a queued connection waiting out a drain. It must succeed."""
    monkeypatch.setattr(server, "_BROKER_CONNECT_RETRY_S", 0.2)
    monkeypatch.setattr(server, "_BROKER_REGISTER_BUDGET_S", 5.0)
    b = StubBroker(dial.admin, delay=1.0).serve()
    try:
        assert server._broker_register(REPORT_ID, "normal", "claude", []) == "TOKEN-1"
    finally:
        b.shutdown()


def test_registration_retries_through_a_socket_that_appears_late(dial, monkeypatch):
    """ENOENT (socket unit restarting), then ECONNREFUSED (bound, not yet
    listening), then served within the short connect retry — one
    registration, no error."""
    monkeypatch.setattr(server, "_BROKER_CONNECT_RETRY_S", 5.0)
    dial.marker.write_text("broker-v1\n")
    b = StubBroker(dial.admin, bind_and_activate=False)

    def bring_up():
        time.sleep(0.4)
        b.server_bind()  # path exists, nobody listening: ECONNREFUSED
        time.sleep(0.4)
        b.server_activate()
        b.serve()

    t = threading.Thread(target=bring_up, daemon=True)
    t.start()
    try:
        token = server._broker_register(REPORT_ID, "normal", "claude", [])
    finally:
        t.join(5)
        b.shutdown()
    assert token == "TOKEN-1"
    assert [(m, p) for m, p, _ in b.requests] == [("POST", "/admin/runs")]


def test_absent_socket_gives_up_after_the_short_retry_not_the_read_budget(dial, monkeypatch):
    monkeypatch.setattr(server, "_BROKER_CONNECT_RETRY_S", 0.5)
    monkeypatch.setattr(server, "_BROKER_REGISTER_BUDGET_S", 30.0)
    t0 = time.monotonic()
    with pytest.raises(server._BrokerUnavailable):
        server._broker_register(REPORT_ID, "normal", "claude", [])
    assert 0.4 < time.monotonic() - t0 < 3


def test_deregistration_never_waits_out_a_drain(dial, monkeypatch):
    """Cleanup on a short timeout: a finished result must not sit behind a
    reload. Failure is logged, not raised (the TTL is the backstop)."""
    monkeypatch.setattr(server, "_BROKER_DEREGISTER_TIMEOUT_S", 0.3)
    monkeypatch.setattr(server, "_BROKER_REGISTER_BUDGET_S", 30.0)
    b = StubBroker(dial.admin, delay=3.0).serve()
    t0 = time.monotonic()
    try:
        server._broker_deregister(REPORT_ID)
    finally:
        b.shutdown()
    assert time.monotonic() - t0 < 1.5
    assert any("deregister failed" in r.getMessage() for r in dial.caplog.records)


def test_checkout_ships_the_protocol_marker_server_reads():
    """The marker must sit where `_egress_mode` looks, saying what the guest
    side (this checkout's run-agent.sh) speaks. A rename on either side would
    keep every dial in legacy mode without a sound."""
    assert server._GUEST_PROTOCOL_PATH.read_text().strip() == server._GUEST_PROTOCOL_BROKER
    run_agent = (server._GUEST_PROTOCOL_PATH.parent / "run-agent.sh").read_text()
    assert f'"{server._GUEST_PROTOCOL_BROKER}"' in run_agent
