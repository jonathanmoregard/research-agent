"""§3.7 drift test: every URL the model is SHOWN must be one it may fetch.

The provenance gate refuses any URL the model constructed. That makes the prompt
and the tool descriptions part of the gate's contract: if they tell the model to
open a URL, the gate has to allow it, or the documented workflow is broken the
first time the model follows instructions. Nothing enforced that agreement, which
is how `https://www.tmdn.org/tmview/` came to sit in the `intercept_page`
description as the template to use while `FIXED_URLS` was empty and the gate
refused it.

So: collect every `https://` literal in the text the model actually reads, and
assert the gate allows it against an EMPTY ledger — empty because these URLs are
entry points, reachable before any search has run. A URL that is not meant to be
opened goes in `DOC_ONLY_URLS` with a reason.

`DOC_ONLY_URLS` is deliberately defined here and not in `scraper/urlpolicy.py`.
It grants nothing: it is a list of strings this test agrees not to check. Putting
it next to `SHOP_TEMPLATES` and `FIXED_URLS` would make it look like a third
operator allowlist, and the next reader would wire it into `check()`.

Scope note: only model-facing TEXT is collected — the markdown prompts,
`DEPTH_GUIDANCE`, and the shims' tool `description` / schema text. Deliberately
NOT the shims' code constants: `https://api.ebay.com/...` and friends are
endpoints the shim or broker calls host-side, never fetch targets for the model,
and sweeping them in would force a pile of exemptions that would hollow out the
test.
"""
from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

from scraper.urlpolicy import Ledger, check

REPO = Path(__file__).resolve().parent.parent

# A URL literal as it appears in prose: stop at whitespace, quotes, brackets and
# the punctuation that normally ends a sentence rather than a URL. `<name>` and
# `{name}` placeholders are matched as PART of the URL rather than ending it —
# otherwise "https://host/<slug>" would be collected as a bare "https://host/" and
# silently judged as an entry point it is not.
_URL_RE = re.compile(r"https://(?:<[A-Za-z_]+>|\{[A-Za-z_]+\}|[^\s\"'`<>{}\\)\]])+")
_TRAILING = ".,;:!?"
_PLACEHOLDER = re.compile(r"<[A-Za-z_]+>|\{[A-Za-z_]+\}")

SHIMS = ("exa_shim", "tavily_shim", "render_shim", "trademark_shim",
         "bolagsverket_shim", "prv_shim", "shopping_shim")

# Never opened by the model. Each entry needs a reason.
DOC_ONLY_URLS: dict[str, str] = {
    # Provider API bases named so the model knows whose index it is searching.
    # The model never fetches them: the shim calls them through the broker.
    "https://api.exa.ai": "Exa API base, named for provenance; called by the shim",
    "https://api.tavily.com": "Tavily API base, named for provenance; called by the shim",
    "https://www.tradera.com": "Tradera site root, named as the marketplace, not a fetch target",
    # Bulk data sources fetched to /tool-cache by their own shim, not rendered.
    "https://vardefulla-datamangder.bolagsverket.se/bolagsverket/bolagsverket_bulkfil.zip":
        "Bolagsverket bulk zip, fetched by bolagsverket_shim to /tool-cache (§0.2)",
    # Shapes, not URLs.
    "https://www.sellpy.se/item/…": "illustrative item-URL shape; carries a literal ellipsis",
    # A base the model is told to CONCATENATE, never to open on its own. CLAUDE.md
    # calls it "the one case where you join a URL yourself"; §3.3 ledgers the joined
    # item URL, which is what actually gets fetched (see
    # test_clas_ohlson_json_render_ledgers_the_joined_item_url).
    "https://www.clasohlson.com/se": "relative_base for joining item paths, not a fetch target",
}


def _model_facing_text() -> dict[str, str]:
    """Source name -> text the model reads."""
    out: dict[str, str] = {}
    for rel in ("agent/CLAUDE.md", "agent/AGENTS.md"):
        path = REPO / rel
        if path.exists():
            out[rel] = path.read_text()

    sys.path.insert(0, str(REPO))
    try:
        server = importlib.import_module("mcp_server.server")
        out["DEPTH_GUIDANCE"] = "\n".join(str(v) for v in server.DEPTH_GUIDANCE.values())
    finally:
        sys.path.remove(str(REPO))

    shim_dir = REPO / "agent" / "shims"
    sys.path.insert(0, str(shim_dir))
    try:
        for name in SHIMS:
            mod = importlib.import_module(name)
            tools = getattr(mod, "TOOLS", [])
            chunks = []
            for tool in tools:
                chunks.append(str(tool.get("description", "")))
                chunks.append(str(tool.get("inputSchema", "")))
            out[f"{name}.TOOLS"] = "\n".join(chunks)
    finally:
        sys.path.remove(str(shim_dir))
    return out


def _candidates() -> list[tuple[str, str]]:
    """(source, url) for every model-facing URL literal, placeholders filled."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for source, text in _model_facing_text().items():
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(_TRAILING)
            # WHERE a placeholder sits decides what the literal is.
            #
            # In the path or host it describes the shape of a URL the model will be
            # HANDED — an item link inside a result list. Those are reachable only
            # through the ledger, so requiring one to pass against an EMPTY ledger
            # would assert the opposite of what the gate is for. Skip them.
            #
            # In the query it is a documented parameter of an entry point the model
            # is told to build (`...?q=<query>`), which is exactly what must stay
            # fetchable. Substitute and check it. §3.7 names the `<query>` case;
            # the rule generalises to any placeholder name.
            head, sep, query = url.partition("?")
            if _PLACEHOLDER.search(head):
                continue
            if sep:
                url = head + sep + _PLACEHOLDER.sub("test", query)
            # A template written as its bare prefix ("...?q="): an empty free
            # parameter is refused by design, so fill it as the model would.
            if url.endswith("="):
                url += "test"
            key = (source, url)
            if key not in seen:
                seen.add(key)
                found.append(key)
    return found


def test_model_facing_text_was_collected():
    """Guard the guard: a refactor that empties the corpus must fail, not pass."""
    sources = _model_facing_text()
    assert "DEPTH_GUIDANCE" in sources and sources["DEPTH_GUIDANCE"].strip()
    assert any(k.endswith(".TOOLS") and sources[k].strip() for k in sources)
    assert len(_candidates()) >= 15, "URL corpus suspiciously small; is _URL_RE still right?"


@pytest.mark.parametrize("source,url", _candidates(), ids=lambda v: v[:60])
def test_every_url_the_model_is_shown_is_fetchable(source, url):
    if url in DOC_ONLY_URLS:
        pytest.skip(f"doc-only: {DOC_ONLY_URLS[url]}")
    verdict = check(url, Ledger())
    assert verdict.allowed, (
        f"{source} shows the model {url!r}, but the gate refuses it "
        f"({verdict.code}: {verdict.reason}). Either add it to urlpolicy "
        f"(SHOP_TEMPLATES or FIXED_URLS) so the documented workflow works, or "
        f"stop showing it to the model, or exempt it in DOC_ONLY_URLS with a reason."
    )
