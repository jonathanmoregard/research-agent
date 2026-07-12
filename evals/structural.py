"""Deterministic quality checks on a research report. No LLM calls."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REQUIRED_SECTIONS = ["## Summary", "## Findings", "## Sources", "## Suspicious content"]
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")


@dataclass
class StructuralResult:
    ok: bool
    failures: list[str] = field(default_factory=list)


def check_report(text: str) -> StructuralResult:
    failures: list[str] = []

    for section in REQUIRED_SECTIONS:
        if section not in text:
            failures.append(f"missing section: {section}")

    findings = _section_body(text, "## Findings")
    sources = _section_body(text, "## Sources")
    source_urls = {url for _, url in _LINK.findall(sources)}

    for line in findings.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        urls = [url for _, url in _LINK.findall(line)]
        if not urls and not _is_marked_unverified(line):
            failures.append(f"uncited finding: {line[:80]}")
        for url in urls:
            if url not in source_urls:
                failures.append(f"cited URL not in Sources: {url}")

    return StructuralResult(ok=not failures, failures=failures)


def _section_body(text: str, header: str) -> str:
    if header not in text:
        return ""
    body = text.split(header, 1)[1]
    nxt = body.find("\n## ")
    return body[:nxt] if nxt != -1 else body


def _is_marked_unverified(line: str) -> bool:
    lowered = line.lower()
    return "unverified" in lowered or "could not verify" in lowered
