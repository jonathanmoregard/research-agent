"""Tests for sourcing claude-token from ~/.claude/.credentials.json.

Behavior under test (mcp_server.server._secrets / _resolve_secret /
_load_claude_credentials_token):

- Reads `claudeAiOauth.accessToken` from the file when env is unset.
- Re-resolves the token on every `_secrets()` call so a `claude /login`
  refresh propagates without a server respawn.
- Env (CLAUDE_CODE_OAUTH_TOKEN) takes precedence over the file.
- Falls back to the keyring when both env and the file miss.
- Symlinks at the credentials path are rejected (O_NOFOLLOW).
- Missing file, oversized file, malformed JSON, or missing nested key
  all fall through to the next source without raising.
- The token value is never logged (sanity check: log file does not
  contain the token bytes after a resolve).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest


@pytest.fixture
def fresh_server(monkeypatch):
    """Reload the module with cleared caches per test, env defaults cleared."""
    from mcp_server import server

    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(server, "_keyring_lookup", lambda key: None)
    server.SECRETS_CACHE.clear()
    yield server
    server.SECRETS_CACHE.clear()


def _write_creds(path: Path, access_token: str | None = "test-access-token") -> None:
    payload: dict = {"claudeAiOauth": {}}
    if access_token is not None:
        payload["claudeAiOauth"]["accessToken"] = access_token
        payload["claudeAiOauth"]["refreshToken"] = "rt-test"
        payload["claudeAiOauth"]["expiresAt"] = 9999999999999
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)


def test_credentials_file_provides_token_when_env_unset(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    _write_creds(creds, "from-creds-file")
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)

    out = fresh_server._secrets()
    assert out.get("claude-token") == "from-creds-file"


def test_env_takes_precedence_over_credentials_file(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    _write_creds(creds, "from-creds-file")
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-env")

    out = fresh_server._secrets()
    assert out.get("claude-token") == "from-env"


def test_token_reresolved_per_call_picks_up_login_refresh(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    _write_creds(creds, "old-token")
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)

    out1 = fresh_server._secrets()
    assert out1.get("claude-token") == "old-token"

    # Simulate `claude /login` rewriting the file.
    _write_creds(creds, "new-token-after-refresh")

    out2 = fresh_server._secrets()
    assert out2.get("claude-token") == "new-token-after-refresh"


def test_missing_credentials_file_falls_through_to_keyring(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"  # not created
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(
        fresh_server,
        "_keyring_lookup",
        lambda k: "from-keyring" if k == "claude-token" else None,
    )
    out = fresh_server._secrets()
    assert out.get("claude-token") == "from-keyring"


def test_credentials_file_with_missing_access_token_falls_through(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    # Schema present but accessToken missing.
    creds.write_text(json.dumps({"claudeAiOauth": {"refreshToken": "rt"}}), encoding="utf-8")
    creds.chmod(0o600)
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)
    monkeypatch.setattr(
        fresh_server,
        "_keyring_lookup",
        lambda k: "from-keyring" if k == "claude-token" else None,
    )
    out = fresh_server._secrets()
    assert out.get("claude-token") == "from-keyring"


def test_credentials_file_with_malformed_json_falls_through(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    creds.write_text("not json {{{", encoding="utf-8")
    creds.chmod(0o600)
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)

    out = fresh_server._secrets()
    assert "claude-token" not in out  # nothing else falls back to


def test_credentials_file_oversized_is_rejected(fresh_server, tmp_path, monkeypatch):
    creds = tmp_path / ".credentials.json"
    # > 16 KiB cap in _load_claude_credentials_token
    creds.write_text(
        '{"claudeAiOauth":{"accessToken":"' + "x" * (17 * 1024) + '"}}',
        encoding="utf-8",
    )
    creds.chmod(0o600)
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)

    out = fresh_server._secrets()
    assert "claude-token" not in out


def test_credentials_file_symlink_is_rejected(fresh_server, tmp_path, monkeypatch):
    real = tmp_path / "real.json"
    _write_creds(real, "would-leak")
    link = tmp_path / ".credentials.json"
    link.symlink_to(real)
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", link)

    out = fresh_server._secrets()
    assert "claude-token" not in out


def test_token_value_never_appears_in_log_file(fresh_server, tmp_path, monkeypatch):
    """A successful resolve must not write the token bytes to server.log.

    Doesn't verify every log handler — just that the file logger
    installed at module import time doesn't carry the secret. Smoke
    check; defense in depth against accidental %s formatting of the
    secret value into a log message.
    """
    log_path = tmp_path / "server.log"
    monkeypatch.setenv("RESEARCH_AGENT_LOG", str(log_path))

    # Re-install the file handler against the test path. The module's
    # global handler points at the old path; install a fresh handler
    # rooted at our temp file.
    fresh_server._LOG.handlers.clear()
    setattr(fresh_server._LOG, "_ra_handler_installed", False)
    fresh_server._LOG_PATH = log_path
    handler = logging.handlers.RotatingFileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    fresh_server._LOG.addHandler(handler)
    fresh_server._LOG.setLevel(logging.INFO)

    creds = tmp_path / ".credentials.json"
    _write_creds(creds, "ULTRA-SECRET-TOKEN-VALUE")
    monkeypatch.setattr(fresh_server, "_CLAUDE_CREDENTIALS_PATH", creds)

    # Trigger every code path that touches the token.
    out = fresh_server._secrets()
    assert out["claude-token"] == "ULTRA-SECRET-TOKEN-VALUE"
    fresh_server._LOG.info("post-resolve sanity ping")

    for h in fresh_server._LOG.handlers:
        h.flush()
    body = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert "ULTRA-SECRET-TOKEN-VALUE" not in body
