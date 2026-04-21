#!/usr/bin/env python3
"""Stdio MCP server exposing Tavily search/extract via tavily-python SDK.

Bypasses the hosted `mcp.tavily.com` (OAuth-gated in remote MCP mode) and
Smithery-wrapped `tavily-mcp` (breaks under Claude Code spawn path in
bwrap; see sibling exa_shim.py).

Protocol: MCP 2024-11-05 over stdio, JSON-RPC 2.0 line-delimited.
"""
from __future__ import annotations

import json
import os
import sys

from curl_cffi import requests as cfrequests  # type: ignore

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")
TAVILY_BASE = "https://api.tavily.com"
IMPERSONATE = "chrome"


def _post(path: str, payload: dict) -> dict:
    if not TAVILY_API_KEY:
        raise RuntimeError("TAVILY_API_KEY not set in shim environment")
    r = cfrequests.post(
        f"{TAVILY_BASE}{path}",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {TAVILY_API_KEY}",
        },
        impersonate=IMPERSONATE,
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Tavily HTTP {r.status_code}: {r.text[:500]}")
    return r.json()

TOOLS = [
    {
        "name": "tavily_search",
        "description": "Search the web via Tavily. Returns top N results with snippets and (optionally) an LLM-synthesized answer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "max_results": {"type": "integer", "description": "Max results (1-20)", "default": 5},
                "search_depth": {"type": "string", "enum": ["basic", "advanced"], "default": "basic"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "tavily_extract",
        "description": "Extract content from one or more URLs via Tavily.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Single URL or list of URLs",
                },
            },
            "required": ["urls"],
        },
    },
]

def _tool_tavily_search(args: dict) -> str:
    query = args.get("query") or ""
    max_results = int(args.get("max_results") or 5)
    depth = args.get("search_depth") or "basic"
    resp = _post(
        "/search",
        {
            "query": query,
            "max_results": max(1, min(max_results, 20)),
            "search_depth": depth,
            "include_answer": True,
        },
    )
    lines: list[str] = []
    if resp.get("answer"):
        lines.append(f"Answer: {resp['answer']}\n")
    for r in resp.get("results", []) or []:
        title = r.get("title") or "(untitled)"
        url = r.get("url") or ""
        snippet = (r.get("content") or "")[:1000]
        lines.append(f"Title: {title}\nURL: {url}\n\n{snippet}\n\n---")
    return "\n".join(lines) if lines else "(no results)"


def _tool_tavily_extract(args: dict) -> str:
    urls = args.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    if not isinstance(urls, list):
        raise RuntimeError("urls must be a string or list of strings")
    resp = _post("/extract", {"urls": urls})
    lines: list[str] = []
    for r in resp.get("results", []) or []:
        url = r.get("url") or ""
        content = (r.get("raw_content") or r.get("content") or "")[:4000]
        lines.append(f"URL: {url}\n\n{content}\n\n---")
    for f in resp.get("failed_results", []) or []:
        lines.append(f"FAILED: {f.get('url')}: {f.get('error')}")
    return "\n".join(lines) if lines else "(no results)"


TOOL_IMPL = {
    "tavily_search": _tool_tavily_search,
    "tavily_extract": _tool_tavily_extract,
}

SERVER_INFO = {"name": "tavily-shim", "version": "1.0.0"}
CAPABILITIES = {"tools": {"listChanged": False}}


def _respond(msg_id, result=None, error=None):
    out: dict = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def _handle(msg: dict) -> None:
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _respond(
            msg_id,
            result={
                "protocolVersion": "2024-11-05",
                "capabilities": CAPABILITIES,
                "serverInfo": SERVER_INFO,
            },
        )
        return
    if method == "notifications/initialized":
        return
    if method == "tools/list":
        _respond(msg_id, result={"tools": TOOLS})
        return
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        impl = TOOL_IMPL.get(name)
        if impl is None:
            _respond(msg_id, error={"code": -32601, "message": f"Unknown tool: {name}"})
            return
        try:
            text = impl(arguments)
            _respond(msg_id, result={"content": [{"type": "text", "text": text}]})
        except Exception as e:
            _respond(
                msg_id,
                result={"content": [{"type": "text", "text": f"ERROR: {e}"}], "isError": True},
            )
        return
    if msg_id is not None:
        _respond(msg_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            _handle(msg)
        except Exception as e:
            sys.stderr.write(f"[tavily-shim] unhandled error: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
