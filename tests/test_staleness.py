"""Code-staleness reporting.

The MCP server imports its Python from the working copy at spawn and then
keeps it for the life of the session, while cron pulls the checkout every
30 minutes. A drifted server must say so rather than answer silently with
old code — that silence is what let a merged fix sit unapplied for three
days on 2026-07-29..31.
"""
from __future__ import annotations

import subprocess

import mcp_server.server as server


def test_head_sha_reads_the_repo():
    """Sanity: the helper agrees with git for this very checkout."""
    expected = subprocess.run(
        ["git", "-C", str(server._REPO_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert server._head_sha(server._REPO_ROOT) == expected


def test_head_sha_on_non_repo_is_none(tmp_path):
    assert server._head_sha(tmp_path) is None


def test_head_sha_never_raises_when_git_is_missing(monkeypatch):
    """Staleness is diagnostic; it must never take a research call down."""
    def _no_git(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(subprocess, "run", _no_git)
    assert server._head_sha(server._REPO_ROOT) is None


def test_head_sha_never_raises_on_timeout(monkeypatch):
    def _slow(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=2)
    monkeypatch.setattr(subprocess, "run", _slow)
    assert server._head_sha(server._REPO_ROOT) is None


def test_no_staleness_when_sha_matches(monkeypatch):
    monkeypatch.setattr(server, "_BOOT_SHA", "abc1234")
    monkeypatch.setattr(server, "_head_sha", lambda repo: "abc1234")
    assert server._staleness() is None


def test_staleness_reports_both_shas(monkeypatch):
    monkeypatch.setattr(server, "_BOOT_SHA", "abc1234")
    monkeypatch.setattr(server, "_head_sha", lambda repo: "def5678")
    drift = server._staleness()
    assert drift["running"] == "abc1234"
    assert drift["on_disk"] == "def5678"
    assert "new session" in drift["note"], "must tell the caller the remedy"


def test_unknown_sha_is_not_reported_as_drift(monkeypatch):
    """git unavailable => no claim either way, rather than a false alarm."""
    monkeypatch.setattr(server, "_BOOT_SHA", "abc1234")
    monkeypatch.setattr(server, "_head_sha", lambda repo: None)
    assert server._staleness() is None
    monkeypatch.setattr(server, "_BOOT_SHA", None)
    monkeypatch.setattr(server, "_head_sha", lambda repo: "def5678")
    assert server._staleness() is None


def test_stamped_adds_key_only_when_drifted(monkeypatch):
    monkeypatch.setattr(server, "_staleness", lambda: None)
    assert server._stamped(lambda: {"status": "done"})() == {"status": "done"}

    monkeypatch.setattr(server, "_staleness", lambda: {"running": "a", "on_disk": "b", "note": "n"})
    out = server._stamped(lambda: {"status": "done"})()
    assert out["server_staleness"]["on_disk"] == "b"


def test_stamped_marks_error_paths_too(monkeypatch):
    """A stale server is most often the explanation for an error result,
    so the busy/degraded/failed paths must carry the stamp as well."""
    monkeypatch.setattr(server, "_staleness", lambda: {"running": "a", "on_disk": "b", "note": "n"})
    out = server._stamped(lambda: {"status": "error", "error": "busy"})()
    assert "server_staleness" in out


def test_stamped_passes_through_non_dict(monkeypatch):
    monkeypatch.setattr(server, "_staleness", lambda: {"running": "a", "on_disk": "b", "note": "n"})
    assert server._stamped(lambda: "not-a-dict")() == "not-a-dict"


def test_stamped_preserves_signature_for_schema_generation():
    """FastMCP builds the tool schema from the signature, so the wrapper
    must be transparent — a bare wrapper would publish (*args, **kwargs)
    and silently break the tool's parameters."""
    import inspect
    params = inspect.signature(server.research).parameters
    assert list(params) == ["prompt", "depth", "model"]
    assert server.research.__doc__ and "depth" in server.research.__doc__
