"""Tests for the SSH transport in mcp_server.server._run_agent.

Mocks subprocess.run so we can assert the exact ssh argv and stdin
protocol without needing a running VM. Verifies:

- ssh is invoked (not docker)
- exactly four null-terminated fields land on stdin, in order:
    claude_token, exa_api_key, tavily_api_key, prompt_body
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


def test_run_agent_stdin_is_four_null_terminated_fields():
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
    assert len(fields) == 4, f"expected 4 fields, got {len(fields)}: {fields!r}"
    assert fields[0] == "ct-test"
    assert fields[1] == "exa-test-key"
    assert fields[2] == "tav-test-key"
    assert "the prompt body" in fields[3]


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
