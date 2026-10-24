"""The per-report scan queues for a Lakera slot instead of refusing at once.

The scanner's default wait budget is 0 s, so with the fleet-wide bucket empty
every report fell straight to the strict no-Lakera path (2026-10-03: 15
reports in one evening). `_scan_text` must pass an explicit budget through.
"""
from __future__ import annotations

import injection_scanner.intercept as intercept

from mcp_server import server as srv


def test_scan_text_passes_a_lakera_wait_budget(monkeypatch) -> None:
    seen: dict = {}

    def fake_scan_text(content, **kwargs):
        seen["content"] = content
        seen.update(kwargs)
        return "verdict"

    monkeypatch.setattr(intercept, "scan_text", fake_scan_text)
    assert srv._scan_text("report body") == "verdict"
    assert seen["content"] == "report body"
    assert seen["lakera_max_wait_s"] == srv._SCAN_LAKERA_MAX_WAIT_S == 120.0
