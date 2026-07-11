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
     never sees the rejected text, a reason, or a layer name. Oversized
     responses are rejected without any raw bytes touching disk (no
     disk-exhaust primitive) — the audit row carries a length marker
     only.

Why this exists: FutureSearch's `rationale` is synthesized from web
pages its agents autonomously crawl — indirect prompt injection surface
(OWASP LLM01). The hosted MCP wired directly into Claude Code would
deliver that text unscanned; this gate closes the gap, and the raw
`mcp__futuresearch__futuresearch_results` tool is deny-listed at user
scope so the gate is the only path.
"""
from __future__ import annotations

import json
import math
import os
import re
import stat as stat_mod
import sys
import time
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import mcp_server.server as _server_mod
from mcp_server.server import (
    _LOG,
    _MAX_CONTENT_BYTES,
    _atomic_write_excl,
    _bucket_scan_ms,
    _scan_error_verdict,
    _scan_text,
    _wrap_content,
    _write_quarantine_audit,
)

# The gate shares research-agent's reports/_quarantine zone (already
# deny-listed for Read/Grep/Glob/shell in user-scope settings). Tests
# monkeypatch this module attribute; production follows server.py.
REPORTS_DIR = _server_mod.REPORTS_DIR

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
        only when the entry turns out to be entirely dropped (a
        rejected leaf, or a container beyond the depth limit).
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
    if node is None or isinstance(node, (bool, int)):
        return node, 0
    if isinstance(node, float):
        # json.loads accepts the non-standard Infinity/-Infinity/NaN
        # literals; keeping them would make json.dumps emit non-standard
        # JSON downstream. Finite floats only.
        if math.isfinite(node):
            return node, 0
        return (None, 1) if top else (_DROP, 0)
    if isinstance(node, str) and (_DATE_RX.fullmatch(node) or node == "never"):
        return node, 0
    return (None, 1) if top else (_DROP, 0)


def _scan(content: str):
    """Indirection so tests can monkeypatch scanning at gate scope."""
    return _scan_text(content)


def _assemble_content(result) -> str:
    """Reduce a CallToolResult-shaped object to one untrusted string.

    `structuredContent` wins outright when present: MCP spec-compliant
    servers that send it also duplicate it as a text block for
    backward compatibility, and concatenating both would produce
    unparseable JSON (silently costing the caller the typed skeleton).
    Only when it is absent do we fall back to joining the text blocks.
    """
    structured = getattr(result, "structuredContent", None)
    if structured:
        return json.dumps(structured)
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


async def _fetch_results(task_id: str, token: str) -> str:
    """Call futuresearch_results on the hosted MCP, server-side.

    Returns `structuredContent` (as JSON) when the server provides it,
    else the joined text blocks — see `_assemble_content`. The bytes
    this returns are UNTRUSTED — no caller may place them in a response
    without passing them through the scan path.
    """
    import anyio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {token}"}
    with anyio.fail_after(FETCH_TIMEOUT):
        async with streamablehttp_client(
            FUTURESEARCH_MCP_URL, headers=headers
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "futuresearch_results", {"task_id": task_id}
                )
    return _assemble_content(result)


mcp = FastMCP("futuresearch-gate")


@mcp.tool()
async def forecast_results(task_id: str) -> dict:
    """Fetch FutureSearch task results with injection screening.

    Typed numeric fields (percentiles, probabilities, dates) are
    returned verbatim in `data` — they are safe by construction. All
    free-form text (rationale etc.) is scanned by the layered
    injection-scanner; on pass it is returned in `text`, wrapped in
    untrusted-content tags. On scanner reject the text is quarantined
    and only `data` plus a generic notice is returned.

    Args:
        task_id: The FutureSearch task id from a futuresearch_* submit
            tool (e.g. futuresearch_forecast).

    Returns:
        On pass:   {"status": "done", "gate_id", "data", "fields_withheld",
                    "text", "timings_ms": {"fetch", "scan", "total"}}
        On reject: {"status": "quarantined", "gate_id", "data",
                    "fields_withheld", "error", "timings_ms"} — scan
                    timing bucketized; no reason/snippet/layer info.
        On error:  {"status": "error", "error", "gate_id"?}
    """
    t0 = time.monotonic()
    gate_id = uuid.uuid4().hex
    # Durable file log (~/.cache/research-agent/server.log): stderr from
    # an MCP server is only captured during the connection window, so
    # per-call triage info must go through server.py's rotating logger.
    # task_id is caller-supplied (not attacker web content) — safe to
    # log truncated.
    _LOG.info("gate call id=%s task_id=%s", gate_id, task_id[:64])

    token = _resolve_token()
    if not token:
        return {
            "status": "error",
            "error": (
                "no valid FutureSearch OAuth token — run /mcp in Claude "
                "Code to re-auth the futuresearch server (or set "
                "FUTURESEARCH_OAUTH_TOKEN)"
            ),
        }

    try:
        raw = await _fetch_results(task_id, token)
    except BaseException as exc:  # noqa: BLE001 — timeout/cancel included
        # Exception text can embed response fragments; type name only.
        _LOG.warning(
            "gate fetch failed id=%s type=%s", gate_id, type(exc).__name__
        )
        print(
            f"futuresearch-gate: fetch failed id={gate_id} "
            f"type={type(exc).__name__}",
            file=sys.stderr,
        )
        return {"status": "error", "error": "results fetch failed", "gate_id": gate_id}

    t_fetch = time.monotonic()
    fetch_ms = int((t_fetch - t0) * 1000)

    # Size gate BEFORE any parse/skeleton work: no O(n) parse on content
    # the gate will reject anyway, and no skeleton derived from oversized
    # content ships to the caller.
    oversized = len(raw.encode("utf-8", errors="replace")) > _MAX_CONTENT_BYTES

    data = None
    fields_withheld = 0
    if not oversized:
        # Best-effort typed skeleton: a non-JSON payload just means no
        # structured data — everything then rides the scanned-text path.
        # Broad except is belt-and-braces (json.loads can RecursionError
        # on adversarially deep input); the depth/budget guards inside
        # _typed_skeleton make its own exceptions structurally unlikely.
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None
        if parsed is not None:
            try:
                data, fields_withheld = _typed_skeleton(parsed)
            except Exception as exc:
                _LOG.warning(
                    "gate skeleton failed id=%s type=%s",
                    gate_id, type(exc).__name__,
                )
                print(
                    f"futuresearch-gate: skeleton failed id={gate_id} "
                    f"type={type(exc).__name__}",
                    file=sys.stderr,
                )
                data, fields_withheld = None, 0

    # Scan the FULL raw payload (keys, labels, rationale — everything).
    if oversized:
        from injection_scanner.intercept import Verdict as _V
        verdict = _V(
            ok=False,
            reason=f"oversized:{len(raw)}>{_MAX_CONTENT_BYTES}",
            layers={"size_limit": "oversized"},
            sanitize_stats={},
            sanitized_text="",
        )
    else:
        try:
            verdict = _scan(raw)
        except Exception as exc:
            verdict = _scan_error_verdict(exc)

    # Verdict outcome to the durable log. Reason CODE only (prefix
    # before the first ':'): the full reason can embed a snippet of the
    # scanned bytes (e.g. secret_shape rejects), and server.log is NOT
    # in the deny-listed quarantine zone — full verdicts belong only in
    # audit.jsonl. The code still tells the operator which layer fired.
    _LOG.info(
        "gate scan id=%s ok=%s reason_code=%s",
        gate_id, verdict.ok, verdict.reason.split(":", 1)[0],
    )

    if not verdict.ok:
        quarantine = REPORTS_DIR / "_quarantine"
        try:
            quarantine.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _LOG.error(
                "gate quarantine mkdir failed id=%s type=%s",
                gate_id, type(e).__name__,
            )
            print(
                f"futuresearch-gate: quarantine mkdir failed {gate_id}: {e}",
                file=sys.stderr,
            )
        else:
            # Oversized rejects skip the body write so repeated rejects
            # can't be used as a disk-exhaust primitive; audit row only.
            if not oversized:
                try:
                    _atomic_write_excl(quarantine / f"{gate_id}.md", raw)
                except OSError as e:
                    _LOG.error(
                        "gate quarantine write failed id=%s type=%s",
                        gate_id, type(e).__name__,
                    )
                    print(
                        f"futuresearch-gate: quarantine write failed "
                        f"{gate_id}: {e}",
                        file=sys.stderr,
                    )
            _write_quarantine_audit(
                gate_id,
                f"futuresearch-gate:{task_id}",
                verdict,
                raw if not oversized else f"<oversized:{len(raw)} bytes, not stored>",
                reports_dir=REPORTS_DIR,
            )
        t_done = time.monotonic()
        # Reject-path timing: `scan` is bucketized, and `total` is
        # DERIVED (fetch + bucketized scan), not measured — a precise
        # total would let a caller recover the exact scan duration via
        # total - fetch, defeating _bucket_scan_ms. `fetch` is pre-scan
        # and carries no layer-fingerprint signal, so it stays precise.
        scan_ms = _bucket_scan_ms(int((t_done - t_fetch) * 1000))
        return {
            "status": "quarantined",
            "gate_id": gate_id,
            "data": data,
            "fields_withheld": fields_withheld,
            "error": "scanner rejected forecast text (quarantined); "
                     "typed fields in `data` are still valid",
            "timings_ms": {
                "fetch": fetch_ms,
                "scan": scan_ms,
                "total": fetch_ms + scan_ms,
            },
        }

    wrapped = _wrap_content(gate_id, verdict.sanitized_text, source="futuresearch-gate")
    t_done = time.monotonic()
    return {
        "status": "done",
        "gate_id": gate_id,
        "data": data,
        "fields_withheld": fields_withheld,
        "text": wrapped,
        "timings_ms": {
            "fetch": fetch_ms,
            "scan": int((t_done - t_fetch) * 1000),
            "total": int((t_done - t0) * 1000),
        },
    }


def main() -> None:
    """Entry point for the `futuresearch-gate-mcp` console script.

    Same boot discipline as research-agent-mcp: refresh the scanner
    package, then refuse to serve if the scanner self-test fails. A gate
    with a silently-broken scanner is worse than no gate.
    """
    _server_mod._maybe_update_scanner()
    _server_mod._boot_smoke()
    mcp.run()


if __name__ == "__main__":
    main()
