"""Tests for the SSH transport in mcp_server.server._run_agent.

Mocks subprocess.run so we can assert the exact ssh argv and stdin
protocol without needing a running VM. Verifies:

- ssh is invoked (not docker)
- exactly seven null-terminated fields land on stdin, in order:
    claude_token, codex_auth_json, exa_api_key, tavily_api_key,
    euipo_client_id, euipo_client_secret, prompt_body
- RESEARCH_DEPTH is set on the remote command
- uuid is passed as a positional arg
- timeout propagates
"""
from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("RESEARCH_SSH_HOST", "127.0.0.1")
    monkeypatch.setenv("RESEARCH_SSH_PORT", "2223")
    monkeypatch.setenv("RESEARCH_SSH_KEY", "/fake/key")
    monkeypatch.setenv("RESEARCH_SSH_USER", "agent")
    monkeypatch.setenv("EXA_API_KEY", "exa-test-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tav-test-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "ct-test")
    monkeypatch.setenv("EUIPO_CLIENT_ID", "euipo-id-test")
    monkeypatch.setenv("EUIPO_CLIENT_SECRET", "euipo-secret-test")
    # Point the credentials-file source at a non-existent path. Without
    # this the file source wins (file > env for claude-token) and these
    # wire-format tests would read the developer's real ~/.claude/.credentials.json.
    from mcp_server import server
    monkeypatch.setattr(
        server,
        "_CLAUDE_CREDENTIALS_PATH",
        server.Path("/dev/null/does-not-exist-for-tests"),
    )
    monkeypatch.setattr(
        server,
        "_CODEX_AUTH_PATH",
        server.Path("/dev/null/does-not-exist-for-tests"),
    )
    yield


def _import_server():
    from mcp_server import server
    server.SECRETS_CACHE.clear()
    return server


def test_run_agent_uses_ssh_not_docker():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["input"] = kwargs.get("input")
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        code, _out = server._run_agent(
            prompt="what is the capital of france",
            report_id="deadbeef" * 4,
            depth="normal",
        )

    assert code == 0
    argv = captured["argv"]
    assert argv[0] == "ssh", f"first arg should be ssh, got {argv!r}"
    assert "docker" not in " ".join(argv)
    assert "-i" in argv
    assert "/fake/key" in argv
    assert "-p" in argv
    assert "2223" in argv
    assert "agent@127.0.0.1" in argv
    joined = " ".join(argv)
    assert "RESEARCH_DEPTH=normal" in joined


def test_run_agent_stdin_is_seven_null_terminated_fields():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["input"] = kwargs.get("input", "")
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        server._run_agent(
            prompt="the prompt body",
            report_id="cafef00d" * 4,
            depth="normal",
        )

    data = captured["input"]
    parts = data.split("\0")
    assert parts[-1] == ""
    fields = parts[:-1]
    assert len(fields) == 7
    assert fields[0] == "ct-test"
    assert fields[1] == ""
    assert fields[2] == "exa-test-key"
    assert fields[3] == "tav-test-key"
    assert fields[4] == "euipo-id-test"
    assert fields[5] == "euipo-secret-test"
    assert "the prompt body" in fields[6]


def test_each_provider_receives_only_its_own_auth(monkeypatch):
    server = _import_server()
    monkeypatch.setattr(
        server,
        "_secrets",
        lambda: {
            "claude-token": "claude-private",
            "codex-auth-json": '{"tokens":{"access_token":"codex-private"}}',
            "exa-api-key": "exa",
            "tavily-api-key": "tavily",
        },
    )
    payloads = []

    def fake_run(argv, **kwargs):
        payloads.append(kwargs.get("input", ""))
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        server._dial_agent("x", "a" * 32, "normal", provider="claude")
        server._dial_agent("x", "b" * 32, "normal", provider="codex")

    claude_fields = payloads[0].split("\0")[:-1]
    codex_fields = payloads[1].split("\0")[:-1]
    assert claude_fields[0] == "claude-private"
    assert claude_fields[1] == ""
    assert codex_fields[0] == ""
    assert "codex-private" in codex_fields[1]


def test_run_agent_uuid_passed_as_argv():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    uuid = "11112222333344445555666677778888"
    with patch.object(subprocess, "run", side_effect=fake_run):
        server._run_agent(
            prompt="x",
            report_id=uuid,
            depth="normal",
        )
    joined = " ".join(captured["argv"])
    assert uuid in joined, f"uuid must appear in ssh argv, got: {joined!r}"


def test_run_agent_timeout_propagates():
    server = _import_server()

    def fake_run(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=kw.get("timeout", 1))

    with patch.object(subprocess, "run", side_effect=fake_run):
        with pytest.raises(subprocess.TimeoutExpired):
            server._run_agent(prompt="x", report_id="0" * 32, depth="normal")


def test_run_agent_empty_secrets_still_ships_seven_fields(monkeypatch):
    """If _secrets() returns {} the stdin payload still has exactly seven
    NUL-terminated fields (empty strings for the six missing secrets,
    then the prompt). The guest-side bash reads seven fields regardless;
    auth then fails inside the agent layer with a clear per-tool error
    rather than silently desynchronising the stdin protocol."""
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("EUIPO_CLIENT_ID", raising=False)
    monkeypatch.delenv("EUIPO_CLIENT_SECRET", raising=False)

    server = _import_server()
    # Stub keyring + claude-credentials lookups so no secrets land in
    # the cache and the wire-format check sees a true empty payload.
    monkeypatch.setattr(server, "_keyring_lookup", lambda key: None)
    monkeypatch.setattr(server, "_load_claude_credentials_token", lambda: None)
    monkeypatch.setattr(server, "_load_codex_auth_json", lambda: None)
    server.SECRETS_CACHE.clear()

    captured = {}

    def fake_run(argv, **kwargs):
        captured["input"] = kwargs.get("input", "")
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        server._run_agent(
            prompt="hello world",
            report_id="cafef00d" * 4,
            depth="normal",
        )

    parts = captured["input"].split("\0")
    assert parts[-1] == ""
    fields = parts[:-1]
    assert len(fields) == 7
    assert fields[0] == ""  # claude
    assert fields[1] == ""  # codex auth JSON
    assert fields[2] == ""  # exa
    assert fields[3] == ""  # tavily
    assert fields[4] == ""  # euipo-client-id
    assert fields[5] == ""  # euipo-client-secret
    assert "hello world" in fields[6]


def test_ssh_settings_empty_env_falls_through_to_default(monkeypatch):
    """`export RESEARCH_SSH_KEY=` (empty) must NOT poison ssh's -i path.
    Matches the home-manager wrapper's `${VAR:-default}` semantics."""
    monkeypatch.setenv("RESEARCH_SSH_KEY", "")
    monkeypatch.setenv("RESEARCH_SSH_HOST", "")
    server = _import_server()
    settings = server._ssh_settings()
    assert settings["key"] == "/run/agenix/research-agent-host-key"
    assert settings["host"] == "127.0.0.1"
