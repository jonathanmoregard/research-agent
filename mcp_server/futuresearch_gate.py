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

# Read at import-time on purpose — same convention as server.py's
# _CLAUDE_CREDENTIALS_PATH: the path must be stable for the server's
# lifetime so concurrent callers see a single agreed value. The wrapper
# sets CLAUDE_CREDENTIALS_FILE before spawning the MCP; tests override
# by monkeypatching this module attribute.
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
        # 64 KiB cap (vs server.py's 16 KiB): server.py reads only the
        # claudeAiOauth block, but this file also carries one mcpOAuth
        # entry per connected MCP server. Real files are still well
        # under this; anything larger is not a credentials file.
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
        # Fail closed: only a real, in-the-future epoch-millis expiry is
        # acceptable. Missing/None/string/bool expiresAt -> treat as
        # expired rather than immortal.
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            continue
        if expires_at / 1000 <= time.time():
            continue
        return tok
    return None


# Reject-path survivors. Keys: strict identifier-ish charset, length-capped
# — a snake_case key with a numeric value is not a usable injection
# vehicle, but free-charset keys would be. Values: only types that cannot
# carry instructions. Date strings and the literal "never" are FutureSearch's
# documented date-percentile vocabulary.
_KEY_RX = re.compile(r"^[A-Za-z0-9_.\-]{1,48}$")
_DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SKELETON_MAX_KEYS = 1024
_SKELETON_MAX_DEPTH = 32


class _Drop:
    __slots__ = ()


_DROP = _Drop()


def _typed_skeleton(node, _budget: list[int] | None = None, _depth: int = 0):
    """Walk parsed JSON; keep only injection-proof leaves.

    Returns (skeleton, dropped_count). `dropped_count` counts leaves and
    keys removed — reported to the caller as a number so the response
    can say "N fields withheld" without echoing any of them.

    Bounds, enforced structurally rather than by trusting upstream:
      * Budget: `_budget` is one shared counter for the whole walk,
        consumed by every KEPT entry — dict keys AND list items alike.
        A slot is reserved (decremented) BEFORE recursing into the
        entry's value, so total kept entries can never exceed
        `_SKELETON_MAX_KEYS` even under nesting; the slot is refunded
        only when the entry turns out to be a dropped leaf.
      * Depth: containers deeper than `_SKELETON_MAX_DEPTH` are dropped
        wholesale (counted as one drop at the parent), so adversarially
        deep JSON cannot raise RecursionError.
      * Sentinel containment: the internal `_DROP` marker never escapes
        to callers — a top-level value that would drop (e.g. the whole
        document is one free string) is normalized to (None, 1).
    """
    top = _budget is None
    if top:
        _budget = [_SKELETON_MAX_KEYS]
    dropped = 0
    if isinstance(node, dict):
        if _depth > _SKELETON_MAX_DEPTH:
            return (None, 1) if top else (_DROP, 0)
        out = {}
        for k, v in node.items():
            if not isinstance(k, str) or not _KEY_RX.fullmatch(k):
                dropped += 1
                continue
            if _budget[0] <= 0:
                dropped += 1
                continue
            _budget[0] -= 1  # reserve this entry's slot before recursing
            sub, sub_dropped = _typed_skeleton(v, _budget, _depth + 1)
            dropped += sub_dropped
            if sub is _DROP:
                _budget[0] += 1  # slot unused: dropped entries are free
                dropped += 1
                continue
            out[k] = sub
        return out, dropped
    if isinstance(node, list):
        if _depth > _SKELETON_MAX_DEPTH:
            return (None, 1) if top else (_DROP, 0)
        out = []
        for v in node:
            if _budget[0] <= 0:
                dropped += 1
                continue
            _budget[0] -= 1  # reserve this item's slot before recursing
            sub, sub_dropped = _typed_skeleton(v, _budget, _depth + 1)
            dropped += sub_dropped
            if sub is _DROP:
                _budget[0] += 1  # slot unused: dropped items are free
                dropped += 1
                continue
            out.append(sub)
        return out, dropped
    if node is None or isinstance(node, (bool, int, float)):
        return node, 0
    if isinstance(node, str) and (_DATE_RX.fullmatch(node) or node == "never"):
        return node, 0
    return (None, 1) if top else (_DROP, 0)
