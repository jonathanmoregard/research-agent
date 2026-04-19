"""
Seed prompt-injection scanner.

Regex-only for now. Flags obvious instructions directed at a downstream
reader (the host Claude session) rather than descriptive content. Grows
into an LLM-backed scanner later.

Rules are intentionally noisy at this stage: false positives beat false
negatives. Tune as real reports accumulate.
"""
from __future__ import annotations

import re
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|system)\b.{0,40}\b(instruction|prompt|message|rule)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_swap",
        re.compile(
            r"\b(you\s+are\s+now|from\s+now\s+on(?:\s+you)?|pretend\s+to\s+be|act\s+as(?:\s+a)?|become\s+a)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_tag",
        re.compile(r"<\s*/?\s*(system|assistant|user|tool_result)[\s>]", re.IGNORECASE),
    ),
    (
        "claude_directive",
        re.compile(
            r"\b(claude|assistant|the\s+model)\b[^.\n]{0,60}\b(must|should|always|never|shall)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_request",
        re.compile(
            r"\b(send|post|upload|leak|exfiltrate|forward)\b.{0,40}\b(to|via)\b.{0,40}(https?://|webhook|endpoint)",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_dump_request",
        re.compile(
            r"\b(reveal|print|show|output|dump)\b.{0,40}\b(api[_\s-]?key|password|secret|token|env\s+var|\.env)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_marker",
        re.compile(r"(\x00|\u200b|\u200c|\u200d|\ufeff)"),
    ),
]


def scan_text(text: str) -> tuple[bool, str]:
    """Return (ok, reason). ok=True means no matches found."""
    hits: list[str] = []
    for name, pat in PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0)[:80]
            hits.append(f"{name}: {snippet!r}")
    if hits:
        return False, "; ".join(hits)
    return True, ""


def scan_file(path: Path) -> tuple[bool, str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return scan_text(text)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python -m scanner.regex <file>", file=sys.stderr)
        sys.exit(2)
    ok, reason = scan_file(Path(sys.argv[1]))
    if ok:
        print("pass")
        sys.exit(0)
    print(f"fail: {reason}")
    sys.exit(1)
