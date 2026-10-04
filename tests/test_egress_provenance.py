"""URL-provenance gate: a run fetches only URLs it was given or shown."""
from __future__ import annotations

import pytest

from egress_gate.provenance import (
    Ledger,
    check,
    extract_urls,
    normalize,
    query_is_bounded,
)

# Opaque, key-shaped, but low-entropy so secret scanners stay quiet.
FAKE_KEY = "canary" + "0a1b2c3d" * 4


def _ledger(*texts: str) -> Ledger:
    ledger = Ledger()
    for text in texts:
        ledger.add_text(text)
    return ledger


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("HTTPS://Example.COM", "https://example.com/"),
        ("https://example.com:443/a#frag", "https://example.com/a"),
        ("http://example.com:80/a?b=1", "http://example.com/a?b=1"),
        ("https://example.com:8443/a", "https://example.com:8443/a"),
        ("https://bücher.example/x", "https://xn--bcher-kva.example/x"),
    ],
)
def test_normalize_canonical_forms(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com/",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://user:pw@example.com/",
        "https://@example.com/",
        "https:///nohost",
        "https://example.com:99999/",
        "https://example.com/" + "a" * 5000,
        None,
    ],
)
def test_normalize_refuses_unfetchable(raw):
    assert normalize(raw) is None


def test_extract_urls_from_markdown_and_bare_text():
    text = (
        "See [Widget](https://shop.example/p/1) and https://news.example/a?x=1, "
        "also (https://paren.example/b). Dup https://shop.example/p/1"
    )
    assert extract_urls(text) == [
        "https://shop.example/p/1",
        "https://news.example/a?x=1",
        "https://paren.example/b",
    ]


def test_seen_url_allowed_exactly():
    ledger = _ledger("Title: x\nURL: https://news.example/article?id=7\n")
    assert check("https://news.example/article?id=7", ledger).allowed
    assert check("https://NEWS.example:443/article?id=7#top", ledger).allowed


@pytest.mark.parametrize(
    "attack",
    [
        f"https://evil.example/?k={FAKE_KEY}",
        f"https://news.example/article?id=7&k={FAKE_KEY}",
        f"https://news.example/article?id=7/{FAKE_KEY}",
        f"https://news.example/{FAKE_KEY}",
        f"https://{FAKE_KEY}.news.example/article?id=7",
        "https://news.example/article?id=8",
        "http://news.example/article?id=7",
    ],
)
def test_modified_or_unseen_urls_refused(attack):
    ledger = _ledger("URL: https://news.example/article?id=7")
    verdict = check(attack, ledger)
    assert not verdict.allowed
    assert "never build" in verdict.reason


def test_shop_template_with_human_query_allowed():
    ledger = Ledger()
    for url in (
        "https://www.ikea.com/se/sv/search/?q=soffbord",
        "https://www.kjell.com/se/sok?q=usb-c%20kabel",
        "https://www.amazon.se/s?k=vattenkokare+st%C3%A5l&page=2",
        "https://www.apotea.se/sok/?q=d-vitamin%20vegan&p=2",
        "https://www.elgiganten.se/search/page-2?q=hörlurar",
        "https://www.apohem.se/sok?q=solkr%C3%A4m&count=50&skip=25",
        "https://www.tradera.com/search?q=fujifilm+x100",
    ):
        assert check(url, ledger).allowed, url


@pytest.mark.parametrize(
    "attack",
    [
        f"https://www.ikea.com/se/sv/search/?q={FAKE_KEY}",
        "https://www.ikea.com/se/sv/search/?q=" + "x" * 101,
        "https://www.ikea.com/se/sv/search/?q=soffbord&leak=secret",
        "https://www.ikea.com/se/sv/search/?q=a&q=b",
        "https://www.ikea.com/se/sv/search/?q=",
        "https://www.ikea.com/se/sv/elsewhere/?q=soffbord",
        "http://www.ikea.com/se/sv/search/?q=soffbord",
        "https://www.ikea.com.evil.example/se/sv/search/?q=soffbord",
        "https://www.amazon.se/s?k=x&page=99999",
        "https://www.elgiganten.se/search/page-x?q=a",
        "https://www.ikea.com/se/sv/search/?q=c2stYW50LW9hdDAxLWZha2VrZXk%3D",
    ],
)
def test_shop_template_abuse_refused(attack):
    assert not check(attack, Ledger()).allowed


@pytest.mark.parametrize(
    "value,ok",
    [
        ("usb-c kabel", True),
        ("Pippi Långstrump", True),
        ("B0CHX1W1XY", True),  # ASIN-length product codes stay usable
        ("sony wh-1000xm5", True),
        (FAKE_KEY, False),
        ("deadbeefcafebabe1234", False),
        ("a" * 33, False),
        ("word " * 25, False),
    ],
)
def test_query_bound(value, ok):
    assert query_is_bounded(value) is ok


def test_ledger_counts_and_caps():
    ledger = Ledger()
    added = ledger.add_text(" ".join(f"https://h.example/{i}" for i in range(5000)))
    assert added == 2000
