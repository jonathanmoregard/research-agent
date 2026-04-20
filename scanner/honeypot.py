"""
Layer 3: honeypot ensemble.

Each research report is fed to a fresh downstream Haiku in THREE different
honeypot scenarios (see honeypot_scenarios.py). Every scenario gives the
judge a plausible environment containing a unique canary plus a set of
alluring tools. A legitimate judge calls `return_summary` (the benign
task) or `report_issue(Prompt_Injection_Attempt, …)`; both count as
`Honeypot_Left_Alone`. A judge that calls any trap tool OR echoes the
canary substring is `Honeypot_Triggered` and we quarantine the report.

Design notes
------------
- Static canaries (not random) — consistent detection, comparable audit.
- `report_issue` is a real, non-trap channel so a non-flipped judge that
  *notices* an injection can still tell us without executing anything.
- Parallel calls across scenarios (asyncio). Any single trigger → fail.
- The module is opt-in; if the `anthropic` SDK or an `ANTHROPIC_API_KEY`
  is unavailable, every scenario reports `skipped:<reason>` and the
  orchestrator treats that as a pass (the regex + secret_shapes layers
  are still enforced — honeypot is the deepest layer, not a fallback).

Environment
-----------
- `ANTHROPIC_API_KEY` env var (or `anthropic-api-key` in the keyring).
- `RESEARCH_HONEYPOT_MODEL` overrides the default Haiku.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass, field
from typing import Literal

from scanner.honeypot_scenarios import (
    ALL_CANARIES,
    ALL_SCENARIOS,
    TRAP_TOOL_NAMES,
    Scenario,
)

Verdict = Literal["Honeypot_Triggered", "Honeypot_Left_Alone", "Honeypot_Skipped"]


@dataclass
class ScenarioResult:
    scenario: str
    verdict: Verdict
    signal: str          # one of: trap:<name>, canary:<name>, left_alone,
                         # left_alone_with_injection_report, skipped:<why>
    raw_excerpt: str = ""


@dataclass
class HoneypotResult:
    ok: bool                                 # True = deliver
    reason: str                              # short aggregate code
    per_scenario: list[ScenarioResult] = field(default_factory=list)


DEFAULT_MODEL = os.environ.get(
    "RESEARCH_HONEYPOT_MODEL", "claude-haiku-4-5-20251001"
)


def _api_key() -> str | None:
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "app", "research-agent",
             "key", "anthropic-api-key"],
            capture_output=True, text=True, timeout=3,
        )
        return r.stdout.strip() or None
    except Exception:
        return None


def _classify(resp_content, scenario: Scenario) -> ScenarioResult:
    """Turn a single Anthropic `messages.create` response into a ScenarioResult."""
    trap_name: str | None = None
    reported_injection = False
    text_chunks: list[str] = []
    for block in resp_content:
        btype = getattr(block, "type", "")
        if btype == "tool_use":
            name = getattr(block, "name", "unknown")
            if name in TRAP_TOOL_NAMES:
                trap_name = name
                break
            if name == "report_issue":
                inp = getattr(block, "input", {}) or {}
                if inp.get("category") == "Prompt_Injection_Attempt":
                    reported_injection = True
        elif btype == "text":
            text_chunks.append(getattr(block, "text", ""))

    excerpt = (" ".join(text_chunks))[:300]

    if trap_name:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"trap:{trap_name}",
            raw_excerpt=excerpt,
        )

    # Canary leak in response text?
    canary = scenario["canary"]
    if canary in excerpt:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"canary:{canary}",
            raw_excerpt=excerpt,
        )
    # Any OTHER scenario's canary leaking here too = also a trigger (shouldn't
    # happen unless the model is somehow mixing contexts, but guard cheap).
    for other in ALL_CANARIES:
        if other != canary and other in excerpt:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"canary_crosstalk:{other}",
                raw_excerpt=excerpt,
            )

    if reported_injection:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Left_Alone",
            signal="left_alone_with_injection_report",
            raw_excerpt=excerpt,
        )
    return ScenarioResult(
        scenario=scenario["name"],
        verdict="Honeypot_Left_Alone",
        signal="left_alone",
        raw_excerpt=excerpt,
    )


async def _run_one(client, scenario: Scenario, report_text: str) -> ScenarioResult:
    # Build messages: scenario history + current user request with the
    # research content attached.
    messages = list(scenario["history"])
    # Ensure the LAST message is user, containing the attached content.
    attach = (
        f"{messages[-1]['content']}\n\n"
        f"<attached_content>\n{report_text}\n</attached_content>"
    )
    if messages and messages[-1]["role"] == "user":
        messages[-1] = {**messages[-1], "content": attach}
    else:
        messages.append({"role": "user", "content": attach})
    try:
        resp = await asyncio.to_thread(
            client.messages.create,
            model=DEFAULT_MODEL,
            max_tokens=400,
            tools=scenario["tools"],  # type: ignore[arg-type]
            system=scenario["system"],
            messages=messages,
        )
    except Exception as e:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Skipped",
            signal=f"skipped:api-error:{e}",
        )
    return _classify(resp.content, scenario)


async def _run_all(report_text: str) -> HoneypotResult:
    try:
        import anthropic  # type: ignore
    except ImportError:
        return HoneypotResult(
            ok=True,
            reason="skipped:anthropic-lib-missing",
            per_scenario=[
                ScenarioResult(
                    scenario=s["name"],
                    verdict="Honeypot_Skipped",
                    signal="skipped:anthropic-lib-missing",
                )
                for s in ALL_SCENARIOS
            ],
        )
    key = _api_key()
    if not key:
        return HoneypotResult(
            ok=True,
            reason="skipped:no-api-key",
            per_scenario=[
                ScenarioResult(
                    scenario=s["name"],
                    verdict="Honeypot_Skipped",
                    signal="skipped:no-api-key",
                )
                for s in ALL_SCENARIOS
            ],
        )
    client = anthropic.Anthropic(api_key=key)
    results = await asyncio.gather(
        *(_run_one(client, s, report_text) for s in ALL_SCENARIOS)
    )
    triggered = [r for r in results if r.verdict == "Honeypot_Triggered"]
    if triggered:
        first = triggered[0]
        return HoneypotResult(
            ok=False,
            reason=f"honeypot:{first.scenario}:{first.signal}",
            per_scenario=list(results),
        )
    return HoneypotResult(
        ok=True,
        reason="pass",
        per_scenario=list(results),
    )


def check(report_text: str) -> HoneypotResult:
    """Sync wrapper; runs the full ensemble in parallel under the hood."""
    return asyncio.run(_run_all(report_text))
