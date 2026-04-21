#!/usr/bin/env python3
"""Stdio MCP server exposing Exa search/fetch via curl_cffi.

Bypasses the hosted `mcp.exa.ai`, the Smithery-wrapped `exa-mcp-server`
(breaks under Claude Code spawn path in bwrap), and stock Python HTTP
clients (which Exa's WAF rejects — likely JA3/TLS fingerprint differential
between Node fetch and Python requests/urllib). `curl_cffi` impersonates
a real browser's TLS fingerprint, which Exa accepts.

Protocol: MCP 2024-11-05 over stdio, JSON-RPC 2.0 line-delimited.
"""
from __future__ import annotations

import json
import os
import sys

from curl_cffi import requests as cfrequests  # type: ignore

EXA_API_KEY = os.environ.get("EXA_API_KEY", "")
EXA_BASE = "https://api.exa.ai"
IMPERSONATE = "chrome"

TOOLS = [
    {
        "name": "web_search_exa",
        "description": "Search the web via Exa AI. Returns top N results with highlights.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "numResults": {"type": "integer", "description": "Max results (1-100)", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "web_fetch_exa",
        "description": "Fetch full text content of one or more URLs via Exa.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "urls": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Single URL or list of URLs to fetch",
                },
            },
            "required": ["urls"],
        },
    },
]


def _post(path: str, payload: dict) -> dict:
    if not EXA_API_KEY:
        raise RuntimeError("EXA_API_KEY not set in shim environment")
    r = cfrequests.post(
        f"{EXA_BASE}{path}",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": EXA_API_KEY,
        },
        impersonate=IMPERSONATE,
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Exa HTTP {r.status_code}: {r.text[:500]}")
    return r.json()


def _format_result(r: dict) -> str:
    title = r.get("title") or "(untitled)"
    url = r.get("url") or ""
    published = r.get("publishedDate") or "N/A"
    author = r.get("author") or "N/A"
    hl = r.get("highlights") or []
    text = r.get("text") or ""
    body = "\n".join(hl) if hl else text[:2000]
    return f"Title: {title}\nURL: {url}\nPublished: {published}\nAuthor: {author}\n\n{body}\n\n---"


def _tool_web_search_exa(args: dict) -> str:
    query = args.get("query") or ""
    num = int(args.get("numResults") or 5)
    num = max(1, min(num, 100))
    body = _post(
        "/search",
        {
            "query": query,
            "type": "auto",
            "numResults": num,
            "contents": {"highlights": True},
        },
    )
    return "\n".join(_format_result(r) for r in (body.get("results") or [])) or "(no results)"


def _tool_web_fetch_exa(args: dict) -> str:
    urls = args.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    if not isinstance(urls, list):
        raise RuntimeError("urls must be a string or list of strings")
    body = _post("/contents", {"urls": urls, "text": True})
    return "\n".join(_format_result(r) for r in (body.get("results") or [])) or "(no results)"


TOOL_IMPL = {
    "web_search_exa": _tool_web_search_exa,
    "web_fetch_exa": _tool_web_fetch_exa,
}

SERVER_INFO = {"name": "exa-shim", "version": "1.0.0"}
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
            sys.stderr.write(f"[exa-shim] unhandled error: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
