import json
import time

import pytest

from mcp_server import futuresearch_gate as gate


_UNSET = object()


def _write_creds(tmp_path, access_token="tok-abc", expires_in_s=3600,
                 server_key="futuresearch|78410152cc23cd23",
                 server_url="https://mcp.futuresearch.ai/mcp",
                 expires_at=_UNSET, mcp_oauth=_UNSET):
    if expires_at is _UNSET:
        expires_at = int((time.time() + expires_in_s) * 1000)
    if mcp_oauth is _UNSET:
        mcp_oauth = {
            server_key: {
                "serverName": "futuresearch",
                "serverUrl": server_url,
                "accessToken": access_token,
                "refreshToken": "r",
                "expiresAt": expires_at,
            }
        }
    creds = {
        "claudeAiOauth": {"accessToken": "claude-tok"},
        "mcpOAuth": mcp_oauth,
    }
    p = tmp_path / ".credentials.json"
    p.write_text(json.dumps(creds), encoding="utf-8")
    return p


def test_token_from_credentials_file(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, access_token="tok-live")
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    assert gate._resolve_token() == "tok-live"


def test_env_override_wins(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, access_token="tok-file")
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    monkeypatch.setenv("FUTURESEARCH_OAUTH_TOKEN", "tok-env")
    assert gate._resolve_token() == "tok-env"


def test_expired_token_returns_none(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, expires_in_s=-60)
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None


def test_missing_file_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", tmp_path / "nope.json")
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None


def test_symlinked_credentials_rejected(tmp_path, monkeypatch):
    real = _write_creds(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", link)
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None


def test_wrong_server_url_rejected(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, server_url="https://evil.example.com/mcp")
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None


def test_null_expires_at_fails_closed(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, expires_at=None)
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None


def test_mcp_oauth_not_dict_returns_none(tmp_path, monkeypatch):
    p = _write_creds(tmp_path, mcp_oauth=["not", "a", "dict"])
    monkeypatch.setattr(gate, "_CREDENTIALS_PATH", p)
    monkeypatch.delenv("FUTURESEARCH_OAUTH_TOKEN", raising=False)
    assert gate._resolve_token() is None
