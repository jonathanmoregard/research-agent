"""
Layer 3: multi-provider honeypot ensemble.

Each research report is fed to a fresh downstream model (Haiku, gpt-4o-mini,
gpt-4.1-nano) in three different honeypot scenarios (see
honeypot_scenarios.py). Each scenario defines its own provider + model so
the ensemble spans model families — an injection tuned for one family often
misses on another, and vice versa; diversity is the detection boost.

A legitimate judge calls `return_summary` (the benign task) or
`report_issue(Prompt_Injection_Attempt, …)`; both count as
`Honeypot_Left_Alone`. A judge that calls any trap tool OR echoes the
scenario's canary substring is `Honeypot_Triggered` and the report is
quarantined.

Fail-closed: missing SDK, missing API key, and any per-scenario API
error all collapse to `ok=False`. Silent skip is not allowed — the whole
point of defense-in-depth is that an outage must be visible.
"""
from __future__ import annotations

import asyncio
import json
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
    signal: str
    provider: str = ""
    model: str = ""
    raw_excerpt: str = ""


@dataclass
class HoneypotResult:
    ok: bool
    reason: str
    per_scenario: list[ScenarioResult] = field(default_factory=list)


# ---------- secret loading ----------

def _keyring_env() -> dict[str, str]:
    """Ensure secret-tool can reach the user's D-Bus session bus. MCP-server
    subprocesses may not inherit DBUS_SESSION_BUS_ADDRESS; fall back to the
    systemd per-user path."""
    import pathlib
    env = dict(os.environ)
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus = f"/run/user/{os.getuid()}/bus"
        if pathlib.Path(bus).exists():
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    if "XDG_RUNTIME_DIR" not in env:
        xdg = f"/run/user/{os.getuid()}"
        if pathlib.Path(xdg).is_dir():
            env["XDG_RUNTIME_DIR"] = xdg
    return env


def _keyring(key: str) -> str | None:
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "app", "research-agent", "key", key],
            capture_output=True, text=True, timeout=3,
            env=_keyring_env(),
        )
        return r.stdout.strip() or None
    except Exception:
        return None


def _anthropic_key() -> str | None:
    return os.environ.get("ANTHROPIC_API_KEY") or _keyring("anthropic-api-key")


def _openai_key() -> str | None:
    return os.environ.get("OPENAI_API_KEY") or _keyring("openai-api-key")


# ---------- common classification ----------

def _classify_from_parts(
    scenario: Scenario,
    called_tools: list[tuple[str, dict]],
    text: str,
) -> ScenarioResult:
    """Given the list of (tool_name, tool_input) calls plus any freeform
    text, decide Honeypot_Triggered / Honeypot_Left_Alone."""
    for name, inp in called_tools:
        if name in TRAP_TOOL_NAMES:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"trap:{name}",
                provider=scenario["provider"],
                model=scenario["model"],
                raw_excerpt=text[:300],
            )

    excerpt = text[:300]
    canary = scenario["canary"]
    if canary in text:
        return ScenarioResult(
            scenario=scenario["name"],
            verdict="Honeypot_Triggered",
            signal=f"canary:{canary[:20]}...",
            provider=scenario["provider"],
            model=scenario["model"],
            raw_excerpt=excerpt,
        )
    for other in ALL_CANARIES:
        if other != canary and other in text:
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Triggered",
                signal=f"canary_crosstalk:{other[:20]}...",
                provider=scenario["provider"],
                model=scenario["model"],
                raw_excerpt=excerpt,
            )

    for name, inp in called_tools:
        if name == "report_issue" and inp.get("category") == "Prompt_Injection_Attempt":
            return ScenarioResult(
                scenario=scenario["name"],
                verdict="Honeypot_Left_Alone",
                signal="left_alone_with_injection_report",
                provider=scenario["provider"],
                model=scenario["model"],
                raw_excerpt=excerpt,
            )
    return ScenarioResult(
        scenario=scenario["name"],
        verdict="Honeypot_Left_Alone",
        signal="left_alone",
        provider=scenario["provider"],
        model=scenario["model"],
        raw_excerpt=excerpt,
    )


# ---------- provider adapters ----------

def _openai_tools(tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        out.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        })
    return out


async def _call_anthropic(scenario: Scenario, report_text: str) -> ScenarioResult:
    try:
        import anthropic  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:anthropic-lib-missing",
            provider="anthropic", model=scenario["model"],
        )
    key = _anthropic_key()
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-anthropic-api-key",
            provider="anthropic", model=scenario["model"],
        )
    client = anthropic.Anthropic(api_key=key)
    messages = list(scenario["history"])
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
            model=scenario["model"],
            max_tokens=400,
            tools=scenario["tools"],  # type: ignore[arg-type]
            system=scenario["system"],
            messages=messages,
        )
    except Exception as e:
        # Use only the exception *type* — some SDKs stringify exceptions
        # with request/response fragments, which could echo attacker-shaped
        # content back up into the signal string. The audit record lives in
        # the quarantine zone today, but keep the signal flat by default.
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:anthropic-api-error:{type(e).__name__}",
            provider="anthropic", model=scenario["model"],
        )
    called: list[tuple[str, dict]] = []
    text_chunks: list[str] = []
    for block in resp.content:
        btype = getattr(block, "type", "")
        if btype == "tool_use":
            called.append((
                getattr(block, "name", ""),
                getattr(block, "input", {}) or {},
            ))
        elif btype == "text":
            text_chunks.append(getattr(block, "text", ""))
    return _classify_from_parts(scenario, called, " ".join(text_chunks))


async def _call_openai(scenario: Scenario, report_text: str) -> ScenarioResult:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:openai-lib-missing",
            provider="openai", model=scenario["model"],
        )
    key = _openai_key()
    if not key:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal="unavailable:no-openai-api-key",
            provider="openai", model=scenario["model"],
        )
    client = OpenAI(api_key=key)

    # OpenAI expects flat chat messages; scenario history uses the same
    # role/content shape so we pass it through, then attach the content.
    messages: list[dict] = [{"role": "system", "content": scenario["system"]}]
    messages.extend(scenario["history"])
    attach = (
        f"{messages[-1]['content']}\n\n"
        f"<attached_content>\n{report_text}\n</attached_content>"
    )
    if messages[-1]["role"] == "user":
        messages[-1] = {**messages[-1], "content": attach}
    else:
        messages.append({"role": "user", "content": attach})

    try:
        resp = await asyncio.to_thread(
            client.chat.completions.create,
            model=scenario["model"],
            messages=messages,
            tools=_openai_tools(scenario["tools"]),
            max_tokens=400,
        )
    except Exception as e:
        return ScenarioResult(
            scenario=scenario["name"], verdict="Honeypot_Skipped",
            signal=f"unavailable:openai-api-error:{type(e).__name__}",
            provider="openai", model=scenario["model"],
        )
    msg = resp.choices[0].message
    called: list[tuple[str, dict]] = []
    for tc in (msg.tool_calls or []):
        fn = getattr(tc, "function", None)
        if not fn:
            continue
        try:
            args = json.loads(fn.arguments) if fn.arguments else {}
        except Exception:
            args = {}
        called.append((fn.name, args))
    text = msg.content or ""
    return _classify_from_parts(scenario, called, text)


async def _run_one(scenario: Scenario, report_text: str) -> ScenarioResult:
    if scenario["provider"] == "anthropic":
        return await _call_anthropic(scenario, report_text)
    if scenario["provider"] == "openai":
        return await _call_openai(scenario, report_text)
    return ScenarioResult(
        scenario=scenario["name"], verdict="Honeypot_Skipped",
        signal=f"unavailable:unknown-provider:{scenario['provider']}",
        provider=scenario["provider"], model=scenario["model"],
    )


async def _run_all(report_text: str) -> HoneypotResult:
    results = await asyncio.gather(
        *(_run_one(s, report_text) for s in ALL_SCENARIOS)
    )
    triggered = [r for r in results if r.verdict == "Honeypot_Triggered"]
    if triggered:
        first = triggered[0]
        return HoneypotResult(
            ok=False,
            reason=f"honeypot:{first.scenario}:{first.signal}",
            per_scenario=list(results),
        )
    skipped = [r for r in results if r.verdict != "Honeypot_Left_Alone"]
    if skipped:
        first = skipped[0]
        return HoneypotResult(
            ok=False,
            reason=f"honeypot_unavailable:{first.scenario}:{first.signal}",
            per_scenario=list(results),
        )
    return HoneypotResult(ok=True, reason="pass", per_scenario=list(results))


def check(report_text: str) -> HoneypotResult:
    # The MCP server hosts its tool handlers inside a FastMCP event loop,
    # so a plain asyncio.run() here raises "cannot be called from a running
    # event loop". Run the async ensemble in a fresh worker thread that
    # owns its own loop — keeps this function sync for all callers without
    # leaking async into scanner.intercept.
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run_all(report_text))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(lambda: asyncio.run(_run_all(report_text))).result()
