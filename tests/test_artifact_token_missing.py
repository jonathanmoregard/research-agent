"""The artifact pull/clear calls are best-effort; a missing scraper bearer
token must not turn a scanner reject (or a delivery) into an exception.

fetch_artifacts / discard_artifacts built their request — and so read
/var/lib/scraper-bearer/token — OUTSIDE their try blocks. On any host where
that file is absent (scraper not deployed, token mid-rotation, CI) the
reject path of `_scan_and_deliver` raised FileNotFoundError after
quarantining instead of returning the generic reject. Found when the new CI
ran the suite on a runner without the token (2026-10-04).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import mcp_server.artifact_gate as ag  # noqa: E402


def test_missing_token_fetch_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "SCRAPER_HOST_TOKEN_FILE", str(tmp_path / "absent"))
    assert ag.fetch_artifacts("a" * 32) == []


def test_missing_token_discard_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(ag, "SCRAPER_HOST_TOKEN_FILE", str(tmp_path / "absent"))
    ag.discard_artifacts("a" * 32)
