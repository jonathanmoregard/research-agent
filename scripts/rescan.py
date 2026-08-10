#!/usr/bin/env python3
"""Re-run the scanner on a quarantined report and print layer verdicts.

Safety notes:
  - Prints ONLY per-layer outcomes + reason code + sanitize stats.
  - Never prints sanitized text or raw file content (neither would be safe
    for an interactive Claude Code session).
  - The honeypot layer costs real Anthropic API calls; `--no-honeypot`
    skips it for quick triage. Default keeps it on to match production.

Usage:
  python3 scripts/rescan.py <path-or-uuid> [--no-honeypot]

Examples:
  python3 scripts/rescan.py reports/_quarantine/ffd2ec35...md
  python3 scripts/rescan.py ffd2ec350abd4f8d886012edb762e1fe
  python3 scripts/rescan.py reports/_quarantine/ffd2ec35...md --no-honeypot
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from injection_scanner.intercept import scan as intercept_scan

REPO_ROOT = Path(__file__).resolve().parent.parent


def resolve_path(ref: str) -> Path:
    """Accept either a full path or a bare UUID (looks in reports/_quarantine)."""
    p = Path(ref)
    if p.exists():
        return p
    quarantine = REPO_ROOT / "reports" / "_quarantine"
    # Bare uuid or uuid.md. removesuffix, not rstrip: rstrip strips a CHARACTER
    # SET, so an id ending in 'd', 'm' or '.' would be silently mangled
    # (e.g. "…3ddd".rstrip(".md") -> "…3").
    stem = ref.removesuffix(".md")
    for candidate in (quarantine / f"{stem}.md", quarantine / ref):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"report not found: {ref}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="Path to the report or its UUID.")
    ap.add_argument("--no-honeypot", action="store_true",
                    help="Skip the L3 honeypot layer (saves API calls).")
    args = ap.parse_args()

    path = resolve_path(args.report)
    verdict = intercept_scan(path, use_honeypot=not args.no_honeypot)

    # Never dump sanitized text — sanitize_stats contains the full cleaned
    # text under `text` (a dataclass field), which defeats the quarantine if
    # it reaches an interactive CC session. Strip it.
    stats = {k: v for k, v in verdict.sanitize_stats.items() if k != "text"}

    # `verdict.reason` and `verdict.layers` entries embed up to 80 chars of
    # matched rejected text (regex.py snippet + secret_shapes snippet). If
    # rescan is ever invoked from inside a Claude Code session, stdout flows
    # into that session's context and defeats the quarantine. Redact to the
    # rule-name prefix only before printing.
    audit = {
        "path": str(path),
        "ok": verdict.ok,
        "reason": _redact(verdict.reason),
        "layers": {k: _redact(v) for k, v in verdict.layers.items()},
        "sanitize_stats": stats,
        "raw_size": path.stat().st_size,
        "sanitized_size": len(verdict.sanitized_text),
    }
    print(json.dumps(audit, indent=2, default=str))
    return 0 if verdict.ok else 2


def _redact(reason: str) -> str:
    """Strip matched-text snippets from a reason string, keep rule names.

    Input examples:
        "regex:role_swap: 'you are now a pirate'; secret_shape:aws: 'AKIA...'"
        "fail:role_swap: 'you are now a pirate'"
    Output:
        "regex:role_swap; secret_shape:aws"
        "fail:role_swap"
    Snippets follow a ': <quoted>' pattern; everything after the second
    colon up to the next ';' or end-of-string is the snippet and is
    dropped. Unknown-shape reasons pass through unchanged (no quotes means
    no snippet).
    """
    if not reason or "'" not in reason:
        return reason
    out: list[str] = []
    for part in reason.split(";"):
        part = part.strip()
        q = part.find("'")
        if q < 0:
            out.append(part)
            continue
        head = part[:q].rstrip()
        if head.endswith(":"):
            head = head[:-1].rstrip()
        out.append(head)
    return "; ".join(p for p in out if p)


if __name__ == "__main__":
    sys.exit(main())
