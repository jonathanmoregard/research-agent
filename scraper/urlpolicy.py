"""Egress policy shared by the broker (host) and the scraper (chromium VM).

One module, imported natively by both sides, so the rules cannot drift:

  * URL provenance: which URLs a research run may make a crawler fetch.
    A fetch tool (render_page and friends) must never fetch a URL the model
    built itself — it could carry prompt data or keys to an attacker's
    server. A run may fetch only:
      - a URL that appeared in the user's prompt,
      - a URL returned earlier in the same run by a fixed-endpoint tool
        (search results, shopping listings, register hits) or found on a
        page the run already rendered,
      - an operator-maintained shop search template, where only the query
        parameter is free and it is bounded (short, no opaque tokens, no
        embedded URL),
      - an operator-listed fixed entry URL (exact match only).
  * Typed text: what the agent may type into a page (`fill`, `press`).
  * Search queries: a query sent to a search provider must not be a URL,
    because the provider may crawl it live.
  * Model-chosen numbers that page script can observe (coordinates, scroll,
    waits, viewport): snapped to coarse grids so they carry few bits.

Pure: no I/O, no clocks, stdlib only. The scraper VM mounts only
`scraper/`, and the broker puts exactly `broker/` and `scraper/` on its
path, so this file must not import anything from the repo.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus, urlsplit, urlunsplit

MAX_URL_LEN = 4096
# Free template query: long enough for any product search, too short to
# smuggle much. Opaque runs (base64/hex/keys) are refused outright.
MAX_QUERY_LEN = 100
MAX_TOKEN_LEN = 32
OPAQUE_TOKEN_LEN = 16
# Per-text cap on harvested URLs, so one huge page cannot flood the ledger.
MAX_URLS_PER_TEXT = 2000

_DEFAULT_PORTS = {"http": 80, "https": 443}
# Bare URLs plus markdown `[text](url)` targets; stops at whitespace, quotes,
# angle brackets and the closing paren/bracket of markdown syntax.
_URL_RE = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?"


def normalize(url: str) -> str | None:
    """Canonical form used for ledger keys, or None if not fetchable.

    Lowercases scheme and host, IDNA-encodes the host, drops default ports,
    fragments and userinfo-bearing URLs, and gives an empty path "/".
    The query string is kept byte-for-byte: it is where data would hide.
    """
    if not isinstance(url, str) or len(url) > MAX_URL_LEN:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def extract_urls(text: str, limit: int = MAX_URLS_PER_TEXT) -> list[str]:
    """Normalized http(s) URLs found in tool output or prompt text."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text or ""):
        raw = match.group(0).rstrip(_TRAILING_PUNCT)
        norm = normalize(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
            if len(out) >= limit:
                break
    return out


# A scheme-less "host.tld/path" token in the USER's prompt (people paste
# links without https://). Only used on the prompt, which is trusted input.
_BARE_LINK_RE = re.compile(
    r"(?<![\w@/.:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}/[^\s<>\"'`)\]]*)",
    re.IGNORECASE,
)


def extract_prompt_urls(prompt: str) -> list[str]:
    """URLs in the user's prompt: scheme URLs plus bare `host.tld/path` links.

    A bare link is recorded as https://<link>. The prompt is the one input
    the model did not write, so reading it generously costs nothing.
    """
    out = extract_urls(prompt)
    seen = set(out)
    stripped = _URL_RE.sub(" ", prompt or "")
    for match in _BARE_LINK_RE.finditer(stripped):
        norm = normalize("https://" + match.group(1).rstrip(_TRAILING_PUNCT))
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
            if len(out) >= MAX_URLS_PER_TEXT:
                break
    return out


# --- data-shape rules shared by template params, typed text and queries ----

_SCHEME_MARKER = re.compile(r"://|%3a%2f%2f", re.IGNORECASE)


def has_scheme_marker(value: str) -> bool:
    """True if `value`, raw or after up to three rounds of percent/`+`
    decoding, contains `://` (G1: echo laundering of a URL through a page
    that reflects the query into a link)."""
    cur = value or ""
    for _ in range(4):
        if _SCHEME_MARKER.search(cur):
            return True
        nxt = unquote_plus(cur)
        if nxt == cur:
            return False
        cur = nxt
    return bool(_SCHEME_MARKER.search(cur))


def _opaque(token: str) -> bool:
    return (len(token) >= OPAQUE_TOKEN_LEN and any(c.isdigit() for c in token)
            and any(c.isalpha() for c in token))


def query_is_bounded(value: str) -> bool:
    """True when a free template parameter looks like a human search query."""
    if len(value) > MAX_QUERY_LEN or has_scheme_marker(value):
        return False
    for token in value.split():
        if len(token) > MAX_TOKEN_LEN or _opaque(token):
            return False
    return True


# Text the agent types into pages. Script on an attacker's page can read any
# field the agent fills and send it anywhere (fetch/beacon are subresources,
# deliberately ungated), so typed text is held to the same shape as a shop
# search query: short, human words, no long opaque runs, no URL.
MAX_TYPED_CHARS = MAX_QUERY_LEN  # per call, all fill actions together
MAX_TYPED_TOKEN = MAX_TOKEN_LEN
MAX_KEY_LEN = 32  # press: a key name or chord ("Enter", "Control+A")


def typed_text_error(texts: list[str]) -> str | None:
    """None if the call's typed text is search-query shaped, else why not."""
    if sum(len(t) for t in texts) > MAX_TYPED_CHARS:
        return f"typed text too long (max {MAX_TYPED_CHARS} chars per call)"
    for text in texts:
        if has_scheme_marker(text):
            return "typed text must not contain a URL ('://')"
        for token in text.split():
            if len(token) > MAX_TYPED_TOKEN:
                return f"typed word longer than {MAX_TYPED_TOKEN} chars"
            if _opaque(token):
                return "typed text looks like an opaque token, not a search query"
    return None


PRESS_KEY_RE = re.compile(
    r"^(?:(?:Control|Shift|Alt|Meta)\+)*"
    r"(?:[A-Za-z0-9]|Enter|Tab|Escape|Backspace|Delete|Space"
    r"|Arrow(?:Up|Down|Left|Right)|Home|End|PageUp|PageDown|F[1-9]|F1[0-2])$"
)


def press_key_error(key) -> str | None:
    """None if `key` is a Playwright key name or chord from the allowed set."""
    if not isinstance(key, str) or len(key) > MAX_KEY_LEN or not PRESS_KEY_RE.match(key):
        return ("press key must be a key name such as Enter, Tab, Escape, "
                "ArrowDown, a single letter/digit, or a Control+/Shift+ chord")
    return None


def press_typed_cost(key: str) -> int:
    """Chars a `press` adds to the typed budget: 1 for a printable key."""
    return 1 if len(key.rsplit("+", 1)[-1]) == 1 else 0


# Search query rule (Exa, Tavily). A provider may crawl a URL-shaped query
# live, which would turn a search into a fetch of a model-built URL. A bare
# domain ("ikea.se") stays allowed; a host followed by a path/query/fragment
# with something after the delimiter is refused ("evil.example?k=..."),
# while a version string like "3.12/3" is not (no letters after the dot).
_SEARCH_URLISH = re.compile(r"\.[a-z]{2,}[/?#](?=\S)", re.IGNORECASE)
MAX_DOTTED_TOKEN = 40
SEARCH_QUERY_REFUSAL = "search query must not contain a URL"


def search_query_error(query: str) -> str | None:
    if has_scheme_marker(query) or _SEARCH_URLISH.search(query or ""):
        return SEARCH_QUERY_REFUSAL
    for token in (query or "").split():
        if "." in token and len(token) > MAX_DOTTED_TOKEN:
            return SEARCH_QUERY_REFUSAL
    return None


# --- operator-curated URL shapes --------------------------------------------

@dataclass(frozen=True)
class Template:
    """A shop search URL: fixed scheme/host/path, one bounded free param.

    `extra` names optional parameters with the exact pattern their value
    must match (pagination and the like); anything else in the query refuses.
    `path_re`, when set, replaces the exact path (e.g. /search/page-2).
    `relative_base`, when set, is where root-relative item paths in this
    template's response are joined (see `relative_targets`).
    """

    host: str
    path: str
    param: str
    extra: tuple[tuple[str, str], ...] = ()
    path_re: str | None = None
    relative_base: str | None = None

    def matches(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.netloc != self.host:
            return False
        if self.path_re is not None:
            if not re.fullmatch(self.path_re, parts.path):
                return False
        elif parts.path != self.path:
            return False
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
        names = [k for k, _ in pairs]
        if names.count(self.param) != 1 or len(names) != len(set(names)):
            return False
        allowed_extra = dict(self.extra)
        for key, value in pairs:
            if key == self.param:
                if not value or not query_is_bounded(value):
                    return False
            elif key in allowed_extra:
                if not re.fullmatch(allowed_extra[key], value):
                    return False
            else:
                return False
        # The raw query must not smuggle a URL past parse_qsl either.
        return not has_scheme_marker(parts.query)


_PAGE = r"[0-9]{1,3}"

# Mirrors the Shopping routing table in agent/CLAUDE.md. A row added there
# that renders a search URL needs a row here, or the gate refuses it
# (tests/test_egress_drift.py checks both directions).
SHOP_TEMPLATES: tuple[Template, ...] = (
    Template("www.tradera.com", "/search", "q"),
    Template("www.amazon.se", "/s", "k", (("page", _PAGE),)),
    Template("www.amazon.de", "/s", "k", (("page", _PAGE),)),
    Template("www.vinted.se", "/catalog", "search_text", (("page", _PAGE),)),
    Template("www.ikea.com", "/se/sv/search/", "q"),
    Template("www.clasohlson.com", "/se/search/getSearchResults", "text", (("page", _PAGE),),
             relative_base="https://www.clasohlson.com/se"),
    Template("www.sellpy.se", "/search", "query"),
    Template("www.apotea.se", "/sok", "q", (("p", _PAGE),), path_re=r"/sok/?"),
    Template("www.kjell.com", "/se/sok", "q", (("page", _PAGE),)),
    Template("www.elgiganten.se", "/search", "q", path_re=r"/search(?:/page-[0-9]{1,3})?"),
    Template("www.webhallen.com", "/se/search", "searchString"),
    Template("www.inet.se", "/hitta", "q"),
    Template("www.biltema.se", "/soksida/", "query"),
    Template("www.rusta.com", "/sv-se/sok", "q"),
    Template("www.apohem.se", "/sok", "q", (("count", _PAGE), ("skip", r"[0-9]{1,4}"))),
    Template("lyko.com", "/sv/sok", "q"),
    Template("www.bokus.com", "/search", "q", (("page", _PAGE),)),
)


@dataclass(frozen=True)
class FixedURL:
    """An operator-listed entry point no search returns (SPA start pages).

    Exact URLs only: a prefix entry would give the model a free path suffix,
    which is a data channel. `why` says where the prompt points at it.
    """

    url: str
    why: str


# Empty on purpose (2026-10-04): the only entry the prompt named was TMview,
# whose Legal Notice reserves against automated use, so it was dropped from
# the prompt instead of allow-listed here.
FIXED_URLS: tuple[FixedURL, ...] = ()


# --- relative item paths (Clas Ohlson JSON) ----------------------------------

# A quoted root-relative path: a JSON string value or an href/src attribute.
# No query and no `//` prefix, so it carries nothing beyond what the site
# wrote. Commas and other sub-delimiters occur in real item paths
# ("/Vattenkokare-i-plast,-1,7-liter/p/44-4973").
_REL_PATH_RE = re.compile(r"""["'](/(?!/)[\w.~%/+\-,;:=@!$&()*]{1,300})["']""")


def relative_paths(text: str, limit: int = MAX_URLS_PER_TEXT) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in _REL_PATH_RE.finditer(text or ""):
        path = match.group(1)
        if path not in seen:
            seen.add(path)
            out.append(path)
            if len(out) >= limit:
                break
    return out


def relative_targets(paths: list[str], final_url: str,
                     templates: tuple[Template, ...] = SHOP_TEMPLATES) -> list[str]:
    """Absolute URLs for root-relative `paths` found on the page at `final_url`.

    Each path is resolved against the page's origin, and also joined to the
    `relative_base` of a template the page matched (Clas Ohlson's JSON
    gives item paths relative to https://www.clasohlson.com/se).
    """
    norm = normalize(final_url)
    if norm is None:
        return []
    parts = urlsplit(norm)
    bases = [f"{parts.scheme}://{parts.netloc}"]
    for template in templates:
        if template.relative_base and template.matches(norm):
            bases.append(template.relative_base.rstrip("/"))
    out: list[str] = []
    for path in paths:
        for base in bases:
            target = normalize(base + path)
            if target:
                out.append(target)
    return out


# --- the per-run ledger and the check ----------------------------------------

@dataclass
class Ledger:
    """URLs one research run has legitimately seen.

    `max_urls` caps the total (None = unbounded). At the cap new URLs are
    dropped and `full` is set; later fetches of unseen URLs are refused with
    reason `ledger_full` (fail closed).
    """

    urls: set[str] = field(default_factory=set)
    max_urls: int | None = None
    full: bool = False
    _order: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.urls and not self._order:
            self._order = list(self.urls)

    def add_url(self, url: str) -> bool:
        """Record one URL; True if it was new and fit under the cap."""
        norm = normalize(url)
        if not norm or norm in self.urls:
            return False
        if self.max_urls is not None and len(self.urls) >= self.max_urls:
            self.full = True
            return False
        self.urls.add(norm)
        self._order.append(norm)
        return True

    def add_urls(self, urls) -> int:
        return sum(1 for u in urls if self.add_url(u))

    def add_text(self, text: str) -> int:
        """Record every URL in trusted-provenance text; returns count added."""
        return self.add_urls(extract_urls(text))

    def recent(self, n: int) -> list[str]:
        """Up to n URLs, newest first."""
        return self._order[::-1][:n]

    def __len__(self) -> int:
        return len(self.urls)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    url: str | None = None
    code: str = ""


NOT_IN_LEDGER_REASON = (
    "URL did not come from the prompt, this run's search/shopping/register "
    "results, or a page rendered in this run, and is not a shop search URL. "
    "Use a URL exactly as a tool returned it; never build one."
)


def check(url: str, ledger: Ledger, templates: tuple[Template, ...] = SHOP_TEMPLATES,
          fixed: tuple[FixedURL, ...] = FIXED_URLS) -> Verdict:
    """Decide whether this run may fetch `url`."""
    norm = normalize(url)
    if norm is None:
        return Verdict(False, "not a fetchable http(s) URL", None, "bad_url")
    if norm in ledger.urls:
        return Verdict(True, "seen in this run", norm, "ledger")
    for template in templates:
        if template.matches(norm):
            return Verdict(True, "shop search template", norm, "template")
    for entry in fixed:
        if normalize(entry.url) == norm:
            return Verdict(True, "operator fixed entry URL", norm, "fixed")
    if ledger.full:
        return Verdict(False, "ledger_full: this run has seen too many URLs to "
                       "record more; " + NOT_IN_LEDGER_REASON, norm, "ledger_full")
    return Verdict(False, NOT_IN_LEDGER_REASON, norm, "not_in_ledger")


def same_site(url: str, current_url: str) -> bool:
    """Same host, ignoring one leading `www.` (the §0.4 navigation allowance)."""
    a, b = normalize(url), normalize(current_url)
    if a is None or b is None:
        return False
    ha, hb = urlsplit(a).hostname or "", urlsplit(b).hostname or ""
    return bool(ha) and ha.removeprefix("www.") == hb.removeprefix("www.")


# --- model-chosen numbers that page script can observe -----------------------
# Snapped, not refused: normal browsing never fails on them. Applied by the
# broker before forwarding and again by the scraper (defence in depth); the
# functions are idempotent, so applying them twice changes nothing.

VIEWPORT_PRESETS: tuple[tuple[int, int], ...] = ((1280, 800), (1920, 1080), (390, 844))
DEFAULT_VIEWPORT = {"width": 1280, "height": 800}
GRID_PX = 8
SCROLL_STEP = 100
MAX_SCROLL = 5000
WAIT_STEPS: tuple[int, ...] = (250, 500, 1000, 2000, 5000, 10000, 30000)
# Request-level page-load timeouts keep the existing 60 s ceiling.
TIMEOUT_STEPS: tuple[int, ...] = WAIT_STEPS + (60000,)
DRAG_STEPS: tuple[int, ...] = (5, 10, 20, 50)
HOLD_STEPS: tuple[int, ...] = (0, 250, 500, 1000, 2000)


def _number(v, what: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ValueError(f"{what} must be a number")
    return float(v)


def snap_choice(v, choices: tuple[int, ...], what: str) -> int:
    x = _number(v, what)
    return min(choices, key=lambda c: (abs(c - x), c))


def snap_viewport(v) -> dict:
    """One of the presets; anything that is not one becomes the default."""
    if v is None:
        return dict(DEFAULT_VIEWPORT)
    if not isinstance(v, dict):
        raise ValueError("viewport must be an object {width, height}")
    w, h = v.get("width"), v.get("height")
    if (w, h) in VIEWPORT_PRESETS and not isinstance(w, bool) and not isinstance(h, bool):
        return {"width": int(w), "height": int(h)}
    return dict(DEFAULT_VIEWPORT)


def snap_xy(x, y, viewport: dict) -> tuple[int, int]:
    """Round to the 8 px grid and clamp inside the viewport."""
    fx, fy = _number(x, "x"), _number(y, "y")
    max_x = (int(viewport["width"]) - 1) // GRID_PX * GRID_PX
    max_y = (int(viewport["height"]) - 1) // GRID_PX * GRID_PX
    sx = min(max(int(round(fx / GRID_PX)) * GRID_PX, 0), max_x)
    sy = min(max(int(round(fy / GRID_PX)) * GRID_PX, 0), max_y)
    return sx, sy


def snap_dy(dy) -> int:
    """Multiple of 100 within ±5000; any non-zero scroll moves at least 100."""
    v = _number(dy, "dy")
    if v == 0:
        return 0
    steps = max(1, int(math.floor(abs(v) / SCROLL_STEP + 0.5)))
    return int(math.copysign(min(steps * SCROLL_STEP, MAX_SCROLL), v))


def _snap_target(t: dict, viewport: dict) -> dict:
    if isinstance(t, dict) and not t.get("selector") and not t.get("ref") \
            and "x" in t and "y" in t:
        x, y = snap_xy(t["x"], t["y"], viewport)
        return {"x": x, "y": y}
    return t


def is_xy_target(t) -> bool:
    return (isinstance(t, dict) and not t.get("selector") and not t.get("ref")
            and "x" in t and "y" in t)


def normalize_session_actions(actions: list, viewport: dict) -> list:
    """Snapped copy of browse `act` actions (shapes already validated)."""
    out = []
    for a in actions:
        a = dict(a)
        t = a.get("type")
        if "timeout_ms" in a:
            a["timeout_ms"] = snap_choice(a["timeout_ms"], TIMEOUT_STEPS, "timeout_ms")
        for key in ("target", "from", "to"):
            if key in a:
                a[key] = _snap_target(a[key], viewport)
        if t == "scroll":
            a["dy"] = snap_dy(a["dy"])
        elif t == "wait_ms":
            a["ms"] = snap_choice(a["ms"], WAIT_STEPS, "ms")
        elif t == "drag":
            a["steps"] = snap_choice(a.get("steps", 10), DRAG_STEPS, "steps")
            a["hold_ms"] = snap_choice(a.get("hold_ms", 0), HOLD_STEPS, "hold_ms")
        out.append(a)
    return out


def normalize_intercept_actions(actions: list) -> list:
    """Snapped copy of intercept actions (shapes already validated)."""
    out = []
    for a in actions:
        a = dict(a)
        if "timeout_ms" in a:
            a["timeout_ms"] = snap_choice(a["timeout_ms"], TIMEOUT_STEPS, "timeout_ms")
        if a.get("type") == "wait_for_timeout_ms" and "ms" in a:
            a["ms"] = snap_choice(a["ms"], WAIT_STEPS, "ms")
        out.append(a)
    return out
