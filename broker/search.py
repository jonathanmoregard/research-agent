"""Exa and Tavily search routes (moved out of the in-VM shims)."""
from __future__ import annotations

import json

from broker import upstream
from broker.runs import RouteError
from scraper import urlpolicy

EXA_URL = "https://api.exa.ai/search"
TAVILY_URL = "https://api.tavily.com/search"

MAX_QUERY_CHARS = 2000
EXA_FULL_TEXT_CHARS = 8000


def _query(req: dict) -> str:
    q = req.get("query")
    if not isinstance(q, str) or not q.strip():
        raise RouteError(400, "query is required", "bad_request")
    if len(q) > MAX_QUERY_CHARS:
        raise RouteError(400, f"query too long (max {MAX_QUERY_CHARS} chars)", "bad_request")
    if urlpolicy.search_query_error(q):
        # A provider may crawl a URL-shaped query live (Exa type=auto,
        # Tavily raw content): that would be a fetch of a model-built URL.
        raise RouteError(400, urlpolicy.SEARCH_QUERY_REFUSAL, "search_query_url")
    return q


def _int(req: dict, key: str, default: int, lo: int, hi: int) -> int:
    v = req.get(key, default)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise RouteError(400, f"{key} must be an integer", "bad_request")
    return max(lo, min(int(v), hi))


def _str_list(v) -> list[str]:
    return [s for s in v if isinstance(s, str)] if isinstance(v, list) else []


def _s(v) -> str:
    return v if isinstance(v, str) else ""


def exa_search(ctx: upstream.Ctx, req: dict) -> dict:
    query = _query(req)
    num = _int(req, "numResults", 5, 1, 100)
    full_text = req.get("fullText") is True
    key = ctx.creds.get("exa-api-key", "")
    if not key:
        raise RouteError(503, "Exa not configured", "not_configured")
    ctx.run.spend("exa")
    contents = ({"text": {"maxCharacters": EXA_FULL_TEXT_CHARS}} if full_text
                else {"highlights": True})
    payload = {"query": query, "type": "auto", "numResults": num, "contents": contents}
    status, data = upstream.call(
        ctx, "Exa", "POST", EXA_URL,
        {"Content-Type": "application/json", "x-api-key": key},
        json.dumps(payload).encode("utf-8"), impersonate=True)
    if status >= 400:
        raise RouteError(502, f"Exa HTTP {status}", "upstream", upstream_status=status)
    body = upstream.parse_json("Exa", data)
    results = []
    for r in (body.get("results") or []) if isinstance(body, dict) else []:
        if not isinstance(r, dict):
            continue
        results.append({
            "title": _s(r.get("title")), "url": _s(r.get("url")),
            "publishedDate": _s(r.get("publishedDate")), "author": _s(r.get("author")),
            "highlights": _str_list(r.get("highlights")), "text": _s(r.get("text")),
        })
    for r in results:
        ctx.run.harvest([r["url"]])
        ctx.run.harvest(urlpolicy.extract_urls(r["text"] + "\n" + "\n".join(r["highlights"])))
    return {"results": results}


def tavily_search(ctx: upstream.Ctx, req: dict) -> dict:
    query = _query(req)
    max_results = _int(req, "max_results", 5, 1, 20)
    depth = req.get("search_depth") or "basic"
    if depth not in ("basic", "advanced"):
        raise RouteError(400, "search_depth must be basic or advanced", "bad_request")
    raw = req.get("include_raw_content") is True
    key = ctx.creds.get("tavily-api-key", "")
    if not key:
        raise RouteError(503, "Tavily not configured", "not_configured")
    ctx.run.spend("tavily")
    payload = {"query": query, "max_results": max_results, "search_depth": depth,
               "include_answer": True, "include_raw_content": raw}
    status, data = upstream.call(
        ctx, "Tavily", "POST", TAVILY_URL,
        {"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        json.dumps(payload).encode("utf-8"), impersonate=True)
    if status >= 400:
        raise RouteError(502, f"Tavily HTTP {status}", "upstream", upstream_status=status)
    body = upstream.parse_json("Tavily", data)
    if not isinstance(body, dict):
        body = {}
    results = []
    for r in body.get("results") or []:
        if not isinstance(r, dict):
            continue
        results.append({"title": _s(r.get("title")), "url": _s(r.get("url")),
                        "content": _s(r.get("content")),
                        "raw_content": _s(r.get("raw_content"))})
    for r in results:
        ctx.run.harvest([r["url"]])
        ctx.run.harvest(urlpolicy.extract_urls(r["content"] + "\n" + r["raw_content"]))
    # `answer` is LLM text generated from the model's own query, so it can
    # echo a model-authored URL: shown to the model, never harvested.
    return {"answer": _s(body.get("answer")), "results": results}
