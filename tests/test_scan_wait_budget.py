"""The per-report scan queues for an L2 vendor slot instead of refusing at once.

The scanner's default wait budget is 0 s, so with the fleet-wide bucket empty
every report fell straight to the strict quota fallback (2026-10-03: 15
reports in one evening). `_scan_text` must pass an explicit budget through.
"""
from __future__ import annotations

import inspect

import injection_scanner.intercept as intercept

from mcp_server import server as srv

_REAL_SCAN_TEXT = intercept.scan_text


def _captured_call(monkeypatch) -> dict:
    seen: dict = {}

    def fake_scan_text(content, **kwargs):
        seen["content"] = content
        seen["kwargs"] = kwargs
        return "verdict"

    monkeypatch.setattr(intercept, "scan_text", fake_scan_text)
    assert srv._scan_text("report body") == "verdict"
    return seen


def test_scan_text_passes_an_l2_wait_budget(monkeypatch) -> None:
    seen = _captured_call(monkeypatch)
    assert seen["content"] == "report body"
    assert seen["kwargs"] == {"l2_max_wait_s": srv._SCAN_L2_MAX_WAIT_S}
    assert srv._SCAN_L2_MAX_WAIT_S == 120.0


def test_scan_text_call_matches_the_installed_scanner_signature(monkeypatch) -> None:
    """A keyword the installed scanner does not accept is a TypeError on every
    scan, i.e. every report rejected. Bind against the real signature."""
    seen = _captured_call(monkeypatch)
    inspect.signature(_REAL_SCAN_TEXT).bind(seen["content"], **seen["kwargs"])
