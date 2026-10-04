"""URL-provenance gate: a run fetches only URLs it was given or shown."""
from __future__ import annotations

import pytest

from scraper.urlpolicy import (
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


# --- amendments (docs/egress-broker.md §3.2, §3.3, §3.5, §3.6, §3.7, §2.3) ---

import json  # noqa: E402
import random  # noqa: E402
from pathlib import Path  # noqa: E402

from scraper import urlpolicy  # noqa: E402
from scraper.urlpolicy import (  # noqa: E402
    FixedURL,
    extract_prompt_urls,
    press_key_error,
    press_typed_cost,
    relative_paths,
    relative_targets,
    search_query_error,
    typed_text_error,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.mark.parametrize("value", [
    "https://evil.example/c",
    "https%3A%2F%2Fevil.example%2Fc",
    "https%253A%252F%252Fevil.example",
    "x+https://evil",
])
def test_g1_scheme_in_template_query_refused(value):
    assert not query_is_bounded(value)
    url = "https://www.ikea.com/se/sv/search/?q=" + value.replace(" ", "+")
    assert not check(url, Ledger()).allowed


def test_g1_typed_text_with_scheme_refused():
    assert typed_text_error(["see https://evil"]) is not None
    assert typed_text_error(["usb-c kabel"]) is None


@pytest.mark.parametrize("key,ok", [
    ("Enter", True), ("Tab", True), ("ArrowDown", True), ("a", True), ("7", True),
    ("Control+a", True), ("Shift+Tab", True), ("F12", True), ("Space", True),
    ("Enter Enter", False), ("abc", False), ("/", False), ("F13", False),
    ("Control+", False), ("x" * 40, False), (5, False),
])
def test_press_grammar(key, ok):
    assert (press_key_error(key) is None) is ok


def test_press_cost_counts_printable_keys():
    assert press_typed_cost("a") == 1
    assert press_typed_cost("Shift+A") == 1
    assert press_typed_cost("Enter") == 0
    assert press_typed_cost("Control+Enter") == 0


@pytest.mark.parametrize("query,ok", [
    ("best kettle 2026", True),
    ("ikea.se vattenkokare", True),          # bare domain: users name sites
    ("python 3.12/3.13 changes", True),      # version, not a host
    ("what is next.js?", True),              # delimiter with nothing after it
    ("node.js vs deno", True),
    ("https://evil.example/c?k=1", False),
    ("evil.example?k=secret", False),
    ("evil.example/c/secret", False),
    ("site evil.example#frag", False),
    ("evil.example%3A%2F%2F", False),
    ("http%3A%2F%2Fevil.example", False),
    ("a." + "b" * 40, False),                # dotted token over 40 chars
])
def test_search_query_rule(query, ok):
    assert (search_query_error(query) is None) is ok


def test_fixed_url_exact_only():
    fixed = (FixedURL("https://spa.example/app/", "test entry"),)
    assert check("https://spa.example/app/", Ledger(), fixed=fixed).allowed
    assert check("HTTPS://SPA.example/app/", Ledger(), fixed=fixed).allowed
    assert not check("https://spa.example/app/?q=x", Ledger(), fixed=fixed).allowed
    assert not check("https://spa.example/app/more", Ledger(), fixed=fixed).allowed


def test_clas_ohlson_relative_item_paths_join_to_se():
    body = (FIXTURES / "clasohlson_getSearchResults.json").read_text()
    final = "https://www.clasohlson.com/se/search/getSearchResults?text=vattenkokare"
    paths = relative_paths(body)
    assert "/Vattenkokare-i-plast,-1,7-liter/p/44-4973" in paths
    targets = relative_targets(paths, final)
    joined = "https://www.clasohlson.com/se/Vattenkokare-i-plast,-1,7-liter/p/44-4973"
    assert joined in targets
    # Exactly the URL the prompt tells the model to build.
    ledger = Ledger()
    ledger.add_urls(targets)
    assert check(joined, ledger).allowed
    # Origin resolution is generic and needs no template.
    other = relative_targets(['/a/b'], "https://news.example/x?y=1")
    assert other == ["https://news.example/a/b"]


@pytest.mark.parametrize("text", ['"//evil.example/x"', '"/a?q=1"', "'relative/no-slash'"])
def test_relative_paths_skip_protocol_relative_and_queries(text):
    assert relative_paths(text) == []


def test_ledger_total_cap_fails_closed():
    ledger = Ledger(max_urls=3)
    assert ledger.add_urls([f"https://h.example/{i}" for i in range(5)]) == 3
    assert ledger.full
    verdict = check("https://h.example/4", ledger)
    assert not verdict.allowed and verdict.code == "ledger_full"
    assert check("https://h.example/1", ledger).allowed
    assert ledger.recent(2) == ["https://h.example/2", "https://h.example/1"]


def test_same_site_ignores_leading_www():
    assert urlpolicy.same_site("https://shop.example/s?q=x", "https://www.shop.example/")
    assert not urlpolicy.same_site("https://evil.example/", "https://shop.example/")
    assert not urlpolicy.same_site("https://shop.example.evil/", "https://shop.example/")


def test_prompt_urls_include_bare_links():
    urls = extract_prompt_urls(
        "Compare https://a.example/x and github.com/user/repo, also ikea.se please")
    assert urls == ["https://a.example/x", "https://github.com/user/repo"]


VP = {"width": 1280, "height": 800}


@pytest.mark.parametrize("given,expected", [
    (None, {"width": 1280, "height": 800}),
    ({"width": 1920, "height": 1080}, {"width": 1920, "height": 1080}),
    ({"width": 390, "height": 844}, {"width": 390, "height": 844}),
    ({"width": 1279, "height": 801}, {"width": 1280, "height": 800}),
    ({"width": 1920.0, "height": 1080}, {"width": 1920, "height": 1080}),
])
def test_viewport_presets(given, expected):
    assert urlpolicy.snap_viewport(given) == expected


def test_viewport_malformed_refused():
    with pytest.raises(ValueError):
        urlpolicy.snap_viewport("1280x800")


@pytest.mark.parametrize("x,y,expected", [
    (0, 0, (0, 0)), (3.9, 4.1, (0, 8)), (101.37, 55.5, (104, 56)),
    (-50, 9999, (0, 792)), (1279, 799, (1272, 792)),
])
def test_xy_grid_and_clamp(x, y, expected):
    assert urlpolicy.snap_xy(x, y, VP) == expected


@pytest.mark.parametrize("dy,expected", [
    (0, 0), (50, 100), (-50, -100), (20, 100), (120, 100), (150, 200),
    (-249, -200), (99999, 5000), (-99999, -5000), (3.7, 100),
])
def test_scroll_snap(dy, expected):
    assert urlpolicy.snap_dy(dy) == expected


@pytest.mark.parametrize("v,expected", [
    (1, 250), (300, 250), (400, 500), (1500, 1000), (1501, 2000), (7000, 5000),
    (29000, 30000), (999999, 30000),
])
def test_wait_snap(v, expected):
    assert urlpolicy.snap_choice(v, urlpolicy.WAIT_STEPS, "ms") == expected


def test_timeout_snap_keeps_60s_ceiling():
    assert urlpolicy.snap_choice(60000, urlpolicy.TIMEOUT_STEPS, "t") == 60000
    assert urlpolicy.snap_choice(45000, urlpolicy.TIMEOUT_STEPS, "t") == 30000


def test_drag_snap():
    acts = urlpolicy.normalize_session_actions(
        [{"type": "drag", "from": {"x": 10.3, "y": 11}, "to": {"ref": "e4"},
          "steps": 33, "hold_ms": 777}], VP)
    assert acts == [{"type": "drag", "from": {"x": 8, "y": 8}, "to": {"ref": "e4"},
                     "steps": 20, "hold_ms": 1000}]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "12", True, None])
def test_malformed_numbers_refused(bad):
    with pytest.raises(ValueError):
        urlpolicy.normalize_session_actions([{"type": "scroll", "dy": bad}], VP)


def _numbers(obj, key=None):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _numbers(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _numbers(v, key)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        yield key, obj


def test_property_no_unsnapped_number_survives():
    rng = random.Random(1234)
    allowed = {
        "x": set(range(0, 1280, 8)), "y": set(range(0, 800, 8)),
        "dy": {s * 100 for s in range(-50, 51)}, "ms": set(urlpolicy.WAIT_STEPS),
        "timeout_ms": set(urlpolicy.TIMEOUT_STEPS), "steps": set(urlpolicy.DRAG_STEPS),
        "hold_ms": set(urlpolicy.HOLD_STEPS),
    }

    def f():
        return rng.choice([rng.uniform(-1e5, 1e5), rng.uniform(-3, 3), rng.randint(-10**6, 10**6)])

    for _ in range(300):
        acts = [
            {"type": "click", "target": {"x": f(), "y": f()}, "timeout_ms": abs(f())},
            {"type": "scroll", "dy": f()},
            {"type": "wait_ms", "ms": abs(f()) + 1},
            {"type": "drag", "from": {"x": f(), "y": f()}, "to": {"x": f(), "y": f()},
             "steps": abs(f()), "hold_ms": abs(f())},
            {"type": "hover", "target": {"x": f(), "y": f()}},
        ]
        snapped = urlpolicy.normalize_session_actions(acts, VP)
        for key, n in _numbers(snapped):
            assert n in allowed[key], (key, n)
            assert isinstance(n, int)
        # Idempotent: the scraper re-applies it.
        assert urlpolicy.normalize_session_actions(snapped, VP) == snapped


def test_intercept_snap():
    out = urlpolicy.normalize_intercept_actions([
        {"type": "wait_for_timeout_ms", "ms": 1234, "timeout_ms": 4321},
        {"type": "fill", "selector": "#q", "text": "x"},
    ])
    assert out[0] == {"type": "wait_for_timeout_ms", "ms": 1000, "timeout_ms": 5000}
    assert out[1] == {"type": "fill", "selector": "#q", "text": "x"}


def test_fixture_is_valid_json():
    json.loads((FIXTURES / "clasohlson_getSearchResults.json").read_text())
