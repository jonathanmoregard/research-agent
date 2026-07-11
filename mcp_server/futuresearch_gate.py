"""
futuresearch-gate MCP server (host-side).

Exposes one tool:

    forecast_results(task_id: str) -> dict

Flow per call:
  1. Resolve the FutureSearch OAuth access token — env override
     FUTURESEARCH_OAUTH_TOKEN, else Claude Code's own credential store
     (~/.claude/.credentials.json, `mcpOAuth` section). Claude Code
     refreshes that token itself, so reading the file inherits
     refreshes — same pattern server.py uses for the Claude token.
  2. Act as an MCP *client* against https://mcp.futuresearch.ai/mcp and
     call `futuresearch_results(task_id)` server-side. The raw response
     NEVER enters any LLM context.
  3. Extract a typed skeleton (numbers, bools, nulls, date-shaped
     strings) that is safe by construction, then run the FULL raw text
     through injection_scanner (unicode sanitize -> secret shapes ->
     honeypot).
  4. Scan pass: return skeleton + the sanitized text wrapped in
     untrusted-content tags. Scan reject: quarantine the raw bytes in
     reports/_quarantine/, return skeleton + a generic error. Caller
     never sees the rejected text, a reason, or a layer name.

Why this exists: FutureSearch's `rationale` is synthesized from web
pages its agents autonomously crawl — indirect prompt injection surface
(OWASP LLM01). The hosted MCP wired directly into Claude Code would
deliver that text unscanned; this gate closes the gap, and the raw
`mcp__futuresearch__futuresearch_results` tool is deny-listed at user
scope so the gate is the only path.
"""
from __future__ import annotations

import json
import os
import re
import stat as stat_mod
import time
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

FUTURESEARCH_MCP_URL = os.environ.get(
    "FUTURESEARCH_MCP_URL", "https://mcp.futuresearch.ai/mcp"
)

_CREDENTIALS_PATH = Path(
    os.environ.get("CLAUDE_CREDENTIALS_FILE")
    or (Path.home() / ".claude" / ".credentials.json")
)

# Fetch timeout (seconds). Results retrieval is a quick lookup, not the
# forecast run itself — the async forecast job runs on FutureSearch's
# side and is polled via the (raw, still-allowed) progress tool.
FETCH_TIMEOUT = int(os.environ.get("FUTURESEARCH_GATE_TIMEOUT", "120"))


def _read_credentials_json() -> dict | None:
    """O_NOFOLLOW read of Claude Code's credential store.

    Mirrors server.py's `_load_claude_credentials_token` discipline:
    symlink at the path -> refuse; non-regular file -> refuse; oversized
    -> refuse. Returns the parsed dict or None. Never logs contents.
    """
    try:
        fd = os.open(
            _CREDENTIALS_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            return None
        if st.st_size > 64 * 1024:
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            data = f.read(64 * 1024 + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        creds = json.loads(data)
    except json.JSONDecodeError:
        return None
    return creds if isinstance(creds, dict) else None


def _resolve_token() -> str | None:
    """FUTURESEARCH_OAUTH_TOKEN env wins; else the credential store.

    The store keys mcpOAuth entries as "<serverName>|<hash>"; match on
    the serverName prefix AND validate the serverUrl so a same-named
    entry for a different host can't be picked up. Expired tokens
    (expiresAt is epoch-millis) resolve to None — the caller surfaces a
    re-auth hint. Empty-string env falls through (export X= means
    unset, same convention as server.py's _ssh_settings).
    """
    env_tok = os.environ.get("FUTURESEARCH_OAUTH_TOKEN")
    if env_tok:
        return env_tok
    creds = _read_credentials_json()
    if not creds:
        return None
    mcp_oauth = creds.get("mcpOAuth")
    if not isinstance(mcp_oauth, dict):
        return None
    for key, entry in mcp_oauth.items():
        if not isinstance(entry, dict):
            continue
        if not str(key).startswith("futuresearch|"):
            continue
        if entry.get("serverUrl") != FUTURESEARCH_MCP_URL:
            continue
        tok = entry.get("accessToken")
        expires_at = entry.get("expiresAt")
        if not isinstance(tok, str) or not tok:
            continue
        if isinstance(expires_at, (int, float)) and expires_at / 1000 <= time.time():
            continue
        return tok
    return None
