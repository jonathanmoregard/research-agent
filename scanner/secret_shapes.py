"""
Layer 1b: high-precision secret-shape detectors.

Rule set is adapted from gitleaks / trufflehog / detect-secrets, which ship
~700 rules collectively; we keep only the high-precision subset whose
pattern is specific enough to have near-zero FP in English technical prose.
Research reports about LLM security DO contain strings like
'CLAUDE_CODE_OAUTH_TOKEN=...' — if a fresh real token shape appears in a
report, we want to quarantine, not deliver.

Each rule has:
  name: short id for the verdict
  pattern: compiled regex
  description: short rationale

These are OR'd with scanner/regex.py; both run over the same text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SecretHit:
    name: str
    snippet: str


PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Anthropic keys and tokens.
    ("anthropic_api_key", re.compile(r"sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{80,}")),
    ("anthropic_oauth_token", re.compile(r"sk-ant-oat[0-9]{2}-[A-Za-z0-9_\-]{40,}")),

    # OpenAI keys.
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}")),

    # AWS access keys + secrets. Access key id has a fixed prefix; secret is
    # 40 base64 chars with context word 'secret' nearby.
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANVA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)aws(.{0,20})?(secret|access)[^\n]{0,20}['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
    ),

    # GCP service-account private key JSON has a long RSA line.
    (
        "gcp_private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),

    # GitHub tokens: ghp_ / gho_ / ghu_ / ghs_ / ghr_ / github_pat_.
    ("github_token", re.compile(r"\bgh[psoure]_[A-Za-z0-9]{36,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),

    # Slack.
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),

    # Stripe.
    ("stripe_key", re.compile(r"\b(sk|rk|pk)_(test|live)_[A-Za-z0-9]{24,}\b")),

    # Tavily.
    ("tavily_key", re.compile(r"\btvly-(?:dev-)?[A-Za-z0-9_\-]{20,}\b")),

    # Exa (UUIDv4-shape but prefixed with context; pure UUIDs are too generic
    # to flag, but a UUID next to the word EXA_API_KEY is specific enough).
    (
        "exa_key_context",
        re.compile(
            r"(?i)exa[_\s-]?(?:api[_\s-]?)?key[^\n]{0,30}[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}"
        ),
    ),

    # Bearer <long-token> outside a documented example. We require >=30 chars
    # to avoid "Bearer <token>" placeholders.
    ("bearer_long", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{30,}")),

    # Typical 3-segment JWT (header.payload.sig) each segment >=20 chars.
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"
        ),
    ),

    # Assignment-of-secret style: KEY=VALUE where KEY looks secret-like and
    # VALUE is a long, mostly-entropy string with no whitespace.
    (
        "env_assignment_secret",
        re.compile(
            r"(?mi)^(?:EXA_API_KEY|TAVILY_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\s*=\s*[A-Za-z0-9._/+\-]{15,}\s*$"
        ),
    ),
]


def scan(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for name, pat in PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(SecretHit(name=name, snippet=m.group(0)[:80]))
    return hits
