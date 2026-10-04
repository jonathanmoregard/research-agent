"""URL-provenance gate: which URLs a research run may make a crawler fetch.

A fetch tool (render_page and friends) must never fetch a URL the model
built itself — it could carry prompt data or keys to an attacker's server.
A run may fetch only:

  * a URL that appeared in the user's prompt,
  * a URL returned earlier in the same run by a fixed-endpoint tool (search
    results, shopping listings, register hits) or found on a page the run
    already rendered,
  * an operator-maintained shop search template, where only the query
    parameter is free and it is bounded (short, no long opaque tokens).

This module is pure: no I/O, no clocks. The caller owns where the ledger
lives and how it is fed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

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


def extract_urls(text: str) -> list[str]:
    """Normalized http(s) URLs found in tool output or prompt text."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text or ""):
        raw = match.group(0).rstrip(_TRAILING_PUNCT)
        norm = normalize(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
            if len(out) >= MAX_URLS_PER_TEXT:
                break
    return out


def query_is_bounded(value: str) -> bool:
    """True when a free template parameter looks like a human search query."""
    if len(value) > MAX_QUERY_LEN:
        return False
    for token in value.split():
        if len(token) > MAX_TOKEN_LEN:
            return False
        if len(token) >= OPAQUE_TOKEN_LEN and re.search(r"\d", token) and re.search(r"[A-Za-z]", token):
            return False
    return True


@dataclass(frozen=True)
class Template:
    """A shop search URL: fixed scheme/host/path, one bounded free param.

    `extra` names optional parameters with the exact pattern their value
    must match (pagination and the like); anything else in the query refuses.
    `path_re`, when set, replaces the exact path (e.g. /search/page-2).
    """

    host: str
    path: str
    param: str
    extra: tuple[tuple[str, str], ...] = ()
    path_re: str | None = None

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
        return True


_PAGE = r"[0-9]{1,3}"

# Mirrors the Shopping routing table in agent/CLAUDE.md. A row added there
# that renders a search URL needs a row here, or the gate refuses it.
SHOP_TEMPLATES: tuple[Template, ...] = (
    Template("www.tradera.com", "/search", "q"),
    Template("www.amazon.se", "/s", "k", (("page", _PAGE),)),
    Template("www.amazon.de", "/s", "k", (("page", _PAGE),)),
    Template("www.vinted.se", "/catalog", "search_text", (("page", _PAGE),)),
    Template("www.ikea.com", "/se/sv/search/", "q"),
    Template("www.clasohlson.com", "/se/search/getSearchResults", "text", (("page", _PAGE),)),
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


@dataclass
class Ledger:
    """URLs one research run has legitimately seen."""

    urls: set[str] = field(default_factory=set)

    def add_text(self, text: str) -> int:
        """Record every URL in trusted-provenance text; returns count added."""
        before = len(self.urls)
        self.urls.update(extract_urls(text))
        return len(self.urls) - before

    def add_url(self, url: str) -> None:
        norm = normalize(url)
        if norm:
            self.urls.add(norm)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    url: str | None = None


def check(url: str, ledger: Ledger, templates: tuple[Template, ...] = SHOP_TEMPLATES) -> Verdict:
    """Decide whether this run may fetch `url`."""
    norm = normalize(url)
    if norm is None:
        return Verdict(False, "not a fetchable http(s) URL")
    if norm in ledger.urls:
        return Verdict(True, "seen in this run", norm)
    for template in templates:
        if template.matches(norm):
            return Verdict(True, "shop search template", norm)
    return Verdict(
        False,
        "URL did not come from the prompt, this run's search/shopping/register "
        "results, or a page rendered in this run, and is not a shop search URL. "
        "Use a URL exactly as a tool returned it; never build one.",
        norm,
    )

