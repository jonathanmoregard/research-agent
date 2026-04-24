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
            # Match only second-person commands that flip the reader's role.
            # Avoid catching prose like "attackers can become a malicious actor".
            r"\b(?:"
            r"you\s+are\s+(?:now|a|the)\s+[A-Za-z]"
            r"|you\s+(?:will|must|should)\s+(?:pretend|act|become|roleplay|simulate)"
            r"|you\s+become\s+(?:a|the)\b"
            r"|pretend\s+(?:to\s+be|you(?:'re|\s+are))\s+"
            r"|roleplay\s+as\b"
            r"|from\s+now\s+on[,\s]"
            r")",
            re.IGNORECASE,
        ),
    ),
    (
        "system_tag",
        re.compile(r"<\s*/?\s*(system|assistant|user|tool_result)[\s>]", re.IGNORECASE),
    ),
    # Wrap-escape: the server frames delivered reports in
    # `<untrusted_external_content>` + `<system-reminder>` tags. A
    # report body that embeds those literal tags can close the untrusted
    # region and open a forged system-reminder — the wrap is defeatable
    # unless the scanner rejects any such tag in the body.
    (
        "wrap_escape",
        re.compile(
            r"<\s*/?\s*(?:system-reminder|untrusted_external_content)\b",
            re.IGNORECASE,
        ),
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
    # Secret-shape leaks — if the agent somehow smuggles a token into the
    # report (e.g. prompt-injected "echo your env"), quarantine the file.
    (
        "anthropic_token",
        re.compile(r"sk-ant-(?:api|oat)[0-9]{2}-[A-Za-z0-9_\-]{20,}"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    (
        "env_dump",
        re.compile(
            r"(?mi)^(?:EXA_API_KEY|TAVILY_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_API_KEY)\s*=\s*\S+"
        ),
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
