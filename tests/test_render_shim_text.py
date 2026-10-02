"""render_page text mode and agent-sized output for render_page / intercept_page.

A shop search page renders to ~500 KB of HTML on one line. That overflowed
the agent's tool-result limit, got spooled to a file the agent could not
slice, and no listing was ever read. These tests pin the contract that fixes
it: render_page answers with the page's visible text by default, every
answer fits AGENT_OUTPUT_BYTES, and a long page can be read in slices.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_TOKEN_FILE = REPO_ROOT / "tests" / "_render_shim_token_stub"
_TOKEN_FILE.write_text("test-token\n")
os.environ["SCRAPER_TOKEN_FILE"] = str(_TOKEN_FILE)

from agent.shims import render_shim  # noqa: E402

CAP = render_shim.AGENT_OUTPUT_BYTES


def _stub(monkeypatch, envelope: dict) -> dict:
    seen: dict = {}

    def fake(endpoint_url, payload, timeout_ms, max_bytes=None):
        seen["payload"] = payload
        return envelope

    monkeypatch.setattr(render_shim, "_post_scraper", fake)
    return seen


def _page(text: str, html: str = "<html>raw</html>") -> dict:
    return {
        "status": "ok", "requested_url": "https://shop.example/s?q=x",
        "final_url": "https://shop.example/s?q=x", "http_status": 200,
        "title": "Search", "html": html, "truncated": False,
        "text": text, "text_truncated": False,
    }


def test_render_returns_visible_text_by_default(monkeypatch):
    item = "[Kettle 1.7 L 249 kr](https://shop.example/p/1)"
    _stub(monkeypatch, _page(f"Results\n{item}", html="<script>huge</script>"))
    out = render_shim._tool_render_page({"url": "https://shop.example/s?q=x"})
    assert item in out
    assert "<script>huge</script>" not in out


def test_render_html_format_still_returns_html(monkeypatch):
    _stub(monkeypatch, _page("Results", html="<div id=grid></div>"))
    out = render_shim._tool_render_page(
        {"url": "https://shop.example/s?q=x", "format": "html"})
    assert "<div id=grid></div>" in out


def test_render_output_fits_agent_budget_in_both_formats(monkeypatch):
    big = "x" * (3 * CAP)
    _stub(monkeypatch, _page("\n".join([big[:200]] * 1000), html=big))
    for fmt in ("text", "html"):
        out = render_shim._tool_render_page(
            {"url": "https://shop.example/s?q=x", "format": fmt})
        assert len(out.encode()) <= CAP + 1024, fmt


def test_long_text_can_be_read_in_slices(monkeypatch):
    lines = [f"item {i} — {i} kr" for i in range(20000)]
    _stub(monkeypatch, _page("\n".join(lines)))
    first = render_shim._tool_render_page({"url": "https://shop.example/s?q=x"})
    assert "item 0 —" in first
    assert "offset=" in first  # tells the agent where to continue
    nxt = int(first.split("offset=")[1].split()[0].rstrip(")]."))
    second = render_shim._tool_render_page(
        {"url": "https://shop.example/s?q=x", "offset": nxt})
    assert "item 0 —" not in second
    last_first = [ln for ln in first.splitlines() if ln.startswith("item ")][-1]
    first_second = [ln for ln in second.splitlines() if ln.startswith("item ")][0]
    assert int(first_second.split()[1]) == int(last_first.split()[1]) + 1


def test_render_without_scraper_text_falls_back_to_html(monkeypatch):
    env = _page("")
    del env["text"]
    _stub(monkeypatch, env)
    out = render_shim._tool_render_page({"url": "https://shop.example/s?q=x"})
    assert "<html>raw</html>" in out


def test_slices_split_on_character_boundaries():
    content = "ö" * 30000  # 2-byte chars on one line: no newline to back up to
    first, nxt = render_shim._slice_utf8(content, 0, 40961)
    second, end = render_shim._slice_utf8(content, nxt, 40961)
    assert end is None
    assert len(first) + len(second) == len(content)
    assert nxt == len(first.encode())


def test_intercept_many_captures_with_long_urls_fit_budget(monkeypatch):
    url = "https://api.example/search?" + "q" * 4000
    cap = {
        "request": {"method": "POST", "url": url, "body": "x" * 4000,
                    "body_truncated": False},
        "response": {"status": 200, "url": url, "body": "y" * 50000,
                     "body_truncated": False},
    }
    _stub(monkeypatch, {"status": "ok", "requested_url": "https://s.example",
                        "final_url": "https://s.example", "captured": [cap] * 16})
    out = render_shim._tool_intercept_page({"url": "https://s.example"})
    assert len(out.encode()) <= CAP + 2048
    assert out.count("--- Capture #") == 16


def test_intercept_output_fits_agent_budget(monkeypatch):
    body = '{"hits":[' + ",".join(['{"title":"Kettle","price":249}'] * 20000) + "]}"
    cap = {
        "request": {"method": "POST", "url": "https://x.algolia.net/1/indexes/q",
                    "body": "{}", "body_truncated": False},
        "response": {"status": 200, "url": "https://x.algolia.net/1/indexes/q",
                     "body": body, "body_truncated": False},
    }
    _stub(monkeypatch, {"status": "ok", "requested_url": "https://s.example",
                        "final_url": "https://s.example", "captured": [cap, cap, cap]})
    out = render_shim._tool_intercept_page({"url": "https://s.example"})
    assert len(out.encode()) <= CAP + 2048
    assert out.count("--- Capture #") == 3
    assert '{"title":"Kettle","price":249}' in out
    assert "shim-truncated" in out
