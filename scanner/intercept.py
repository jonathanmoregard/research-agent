"""
Intercept orchestrator: runs the layered shim and produces a single verdict.

Order (each layer can short-circuit):
  L0  unicode_sanitize      — strip covert channels, NFKC normalize, flag anomaly
  L1a regex (scanner.regex) — seed patterns for role-swap, system-tag, etc.
  L1b secret_shapes         — high-precision API-key / JWT / PEM patterns
  L3  honeypot              — tempt a downstream Haiku with trap tools;
                              if the report coerces it into a tool call, fail
  (L2 LLM classifier and L4 LLM-as-judge are planned, not yet wired)

Caller passes the cleaned path and receives a Verdict dict the server can
use both to decide to deliver and to attach audit metadata.

Honeypot is opt-in: the server toggles it with the RESEARCH_HONEYPOT env
var so cheap local tests don't always pay the API call.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from scanner import regex as regex_layer
from scanner import secret_shapes, unicode_sanitize
from scanner.honeypot import check as honeypot_check


@dataclass
class Verdict:
    ok: bool                       # True  -> deliver
    reason: str                    # short code e.g. "pass" / "secret_shape:aws_access_key"
    layers: dict[str, str]         # per-layer outcome for audit
    sanitize_stats: dict           # unicode_sanitize stats
    sanitized_text: str            # cleaned text the server should deliver

    def to_audit(self) -> dict:
        d = asdict(self)
        # Never dump the whole sanitized text into logs — truncate.
        d["sanitized_text"] = d["sanitized_text"][:200] + "..."
        return d


def scan(path: Path, use_honeypot: bool | None = None) -> Verdict:
    """Run all layers on the file at `path`. Returns a Verdict.

    `use_honeypot`: None = use env RESEARCH_HONEYPOT (default off),
                    True/False = override.
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    layers: dict[str, str] = {}

    # L0
    san = unicode_sanitize.sanitize(raw)
    layers["unicode_sanitize"] = (
        f"stripped={san.stripped} bidi={san.bidi_hits} "
        f"tag={san.tag_hits} zw={san.zw_hits} nfkc_changed={san.nfkc_changed}"
    )
    if unicode_sanitize.is_anomalous(san, len(raw)):
        return Verdict(
            ok=False,
            reason=f"unicode_anomaly:stripped={san.stripped}/{len(raw)}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L1a — the pre-existing regex shim, but run over the sanitized text so
    # zero-width obfuscation can't hide matches.
    ok_a, reason_a = regex_layer.scan_text(san.text)
    layers["regex"] = "pass" if ok_a else f"fail:{reason_a[:80]}"
    if not ok_a:
        return Verdict(
            ok=False,
            reason=f"regex:{reason_a}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L1b — secret-shape scan.
    hits = secret_shapes.scan(san.text)
    layers["secret_shapes"] = "pass" if not hits else f"fail:{hits[0].name}"
    if hits:
        return Verdict(
            ok=False,
            reason=f"secret_shape:{hits[0].name}:{hits[0].snippet[:40]}",
            layers=layers,
            sanitize_stats=asdict(san),
            sanitized_text=san.text,
        )

    # L3 honeypot (opt-in).
    if use_honeypot is None:
        use_honeypot = os.environ.get("RESEARCH_HONEYPOT", "") in ("1", "true", "yes")
    if use_honeypot:
        hp = honeypot_check(san.text)
        layers["honeypot"] = hp.reason
        if not hp.ok:
            return Verdict(
                ok=False,
                reason=f"honeypot:{hp.reason}",
                layers=layers,
                sanitize_stats=asdict(san),
                sanitized_text=san.text,
            )
    else:
        layers["honeypot"] = "disabled"

    return Verdict(
        ok=True,
        reason="pass",
        layers=layers,
        sanitize_stats=asdict(san),
        sanitized_text=san.text,
    )
