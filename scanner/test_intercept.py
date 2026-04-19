"""Tests for the layered intercept shim."""
from __future__ import annotations

import tempfile
from pathlib import Path

from scanner import secret_shapes, unicode_sanitize
from scanner.intercept import scan


# ----- unicode_sanitize -----

def test_strips_tag_block():
    # U+E0045 = ASCII smuggler 'E'
    dirty = "Hello\U000E0045World"
    r = unicode_sanitize.sanitize(dirty)
    assert r.tag_hits == 1
    assert "\U000E0045" not in r.text


def test_strips_bidi_override():
    dirty = "safe\u202Emalicious"
    r = unicode_sanitize.sanitize(dirty)
    assert r.bidi_hits == 1
    assert "\u202E" not in r.text


def test_strips_zero_width():
    dirty = "a\u200Bb\u200Cc\u200Dd\uFEFFe"
    r = unicode_sanitize.sanitize(dirty)
    assert r.zw_hits == 4
    assert r.text == "abcde"


def test_nfkc_normalizes():
    # Fullwidth 'A' -> 'A'
    dirty = "\uFF21BC"
    r = unicode_sanitize.sanitize(dirty)
    assert r.text == "ABC"
    assert r.nfkc_changed


def test_benign_prose_untouched():
    text = (
        "# Python 3.13 Release\n\n"
        "Python 3.13 was released in October 2024 with improved REPL."
    )
    r = unicode_sanitize.sanitize(text)
    assert r.stripped == 0
    assert r.text == text


# ----- secret_shapes -----

def test_finds_anthropic_key():
    text = "My key is sk-ant-api01-" + "A" * 95
    hits = secret_shapes.scan(text)
    assert any(h.name == "anthropic_api_key" for h in hits)


def test_finds_anthropic_oauth():
    text = "oauth: sk-ant-oat01-" + "B" * 60
    hits = secret_shapes.scan(text)
    assert any(h.name == "anthropic_oauth_token" for h in hits)


def test_finds_github_token():
    text = "token = ghp_" + "A" * 36
    hits = secret_shapes.scan(text)
    assert any(h.name == "github_token" for h in hits)


def test_finds_env_assignment():
    text = "EXA_API_KEY=abc123def456ghi789jkl\n"
    hits = secret_shapes.scan(text)
    assert any(h.name == "env_assignment_secret" for h in hits)


def test_benign_research_text_no_hits():
    text = (
        "The sk-ant-api prefix is documented in Anthropic's key format."
        "  Tokens begin with gh[psoure]_ for GitHub."
    )
    # discussing prefixes without a real token should NOT fire
    hits = secret_shapes.scan(text)
    assert not hits


# ----- intercept integration -----

def test_orchestrator_passes_clean_report():
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(
            "# Python 3.13\n\n*Sources: 1*\n\n## Summary\nReleased October 2024.\n"
        )
        path = Path(f.name)
    v = scan(path, use_honeypot=False)
    assert v.ok, f"expected pass, got {v.reason}"
    assert v.layers["regex"] == "pass"
    assert v.layers["secret_shapes"] == "pass"


def test_orchestrator_blocks_secret():
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(
            "# Report\n\nLeaked key: sk-ant-oat01-" + "X" * 60 + "\n"
        )
        path = Path(f.name)
    v = scan(path, use_honeypot=False)
    assert not v.ok
    # Either the regex layer or secret_shapes may catch it first; both acceptable.
    assert "anthropic" in v.reason or "secret_shape" in v.reason


def test_orchestrator_blocks_unicode_covert():
    # Above 0.1% density threshold.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("benign \u202Emalicious" * 100)
        path = Path(f.name)
    v = scan(path, use_honeypot=False)
    assert not v.ok
    assert "unicode_anomaly" in v.reason


def test_orchestrator_strips_but_passes_single_zw():
    # Single zero-width in a long doc is below threshold; gets stripped,
    # doesn't fail.
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("clean text " * 500 + "\u200Bcontaminated")
        path = Path(f.name)
    v = scan(path, use_honeypot=False)
    assert v.ok
    assert "\u200B" not in v.sanitized_text
