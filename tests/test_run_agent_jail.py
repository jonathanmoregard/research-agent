"""Regression tests for the agent jail that scripts/run-agent.sh builds.

Runs the real script with a fake `bwrap` first on PATH. The fake records
the argv it was given, scans every file the jail would see from a
per-call bind for the canary key values, and plays the agent: it writes a
report into whatever directory is bound at /scratch.

Invariants pinned (each was violated before the 2026-10-03 fix):
  - no third-party key value is in any file bound into the jail
    (it used to be rendered into .mcp.json in the agent's cwd);
  - the Claude agent's built-in tool set is Write only, and nothing it
    was not pre-approved for can be prompted through;
  - Write is scoped to /scratch, so the RW /tool-cache share is not
    agent-writable;
  - the report still reaches /out and the agent's exit code survives.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_AGENT = REPO_ROOT / "scripts" / "run-agent.sh"
UUID = "0123456789abcdef0123456789abcdef"
# Fake, recognisable values for every third-party key the host ships in.
CANARIES = {
    name: f"CANARY-{name}"
    for name in (
        "EXA_API_KEY", "TAVILY_API_KEY",
        "EUIPO_CLIENT_ID", "EUIPO_CLIENT_SECRET",
        "EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET",
        "TRADERA_APP_ID", "TRADERA_APP_KEY",
    )
}

FAKE_BWRAP = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
binds, scratch = [], None
i = 0
while i < len(argv):
    a = argv[i]
    if a in ("--bind", "--ro-bind"):
        binds.append((argv[i + 1], argv[i + 2]))
        if argv[i + 2] == "/scratch":
            scratch = argv[i + 1]
        i += 3
        continue
    if a == "--":
        break
    i += 1
canaries = json.loads(os.environ["CANARY_JSON"])
hits = []
for src, dst in binds:
    # System trees (/nix/store, /etc, ...) are not per-call; per-call
    # material lives under /tmp or the test's dirs.
    if not (src.startswith("/tmp/") or src.startswith(os.environ["TEST_ROOT"])):
        continue
    paths = [src] if os.path.isfile(src) else [
        os.path.join(d, f) for d, _, fs in os.walk(src) for f in fs]
    for p in paths:
        try:
            data = open(p, errors="replace").read()
        except OSError:
            continue
        hits += [(dst, k) for k, v in canaries.items() if v in data]
json.dump({"argv": argv, "binds": binds, "hits": hits, "scratch": scratch},
          open(os.environ["BWRAP_LOG"], "w"))
if scratch:
    open(os.path.join(scratch, os.environ["REPORT_NAME"]), "w").write("# report\nok\n")
sys.exit(int(os.environ.get("FAKE_RC", "0")))
'''


@pytest.fixture
def jail(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "bwrap"
    fake.write_text(FAKE_BWRAP)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    out = tmp_path / "out"
    out.mkdir()
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("research something")

    def run(provider="claude", rc=0):
        log = tmp_path / "bwrap.json"
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "RESEARCH_REPORTS_DIR": str(out),
            "RESEARCH_MEM_MAX": "off",
            "RESEARCH_PROVIDER": provider,
            "RESEARCH_DEPTH": "normal",
            "BWRAP_LOG": str(log),
            "CANARY_JSON": json.dumps(CANARIES),
            "TEST_ROOT": str(tmp_path),
            "REPORT_NAME": f"{UUID}.md",
            "FAKE_RC": str(rc),
            "CLAUDE_CODE_OAUTH_TOKEN": "CANARY-CLAUDE-TOKEN",
            **CANARIES,
        }
        p = subprocess.run(["bash", str(RUN_AGENT), UUID, str(prompt)],
                           env=env, capture_output=True, text=True, timeout=60)
        rec = json.loads(log.read_text()) if log.exists() else None
        return p, rec, out / f"{UUID}.md"

    return run


def _agent_argv(rec):
    argv = rec["argv"]
    return argv[argv.index("--") + 1:]


def _flag(argv, name):
    return argv[argv.index(name) + 1]


def test_no_key_value_in_any_file_the_jail_sees(jail):
    p, rec, _ = jail()
    assert p.returncode == 0, p.stderr
    assert rec["hits"] == [], f"canary keys visible inside the jail: {rec['hits']}"
    # The shipped MCP config itself carries no secret placeholders either.
    mcp = (REPO_ROOT / "agent" / ".mcp.json").read_text()
    assert "${" not in mcp, "agent/.mcp.json must not template anything"
    # Nothing is bound over /workspace/agent/.mcp.json any more.
    assert all(dst != "/workspace/agent/.mcp.json" for _, dst in rec["binds"])


def test_claude_builtin_tools_are_write_only(jail):
    _, rec, _ = jail()
    argv = _agent_argv(rec)
    assert argv[:2] == ["claude", "-p"]
    assert _flag(argv, "--tools") == "Write"
    assert _flag(argv, "--permission-mode") == "dontAsk"
    denied = set(_flag(argv, "--disallowed-tools").split(","))
    assert {"Read", "Glob", "Grep", "Bash", "WebFetch", "WebSearch"} <= denied


def test_write_is_scoped_to_scratch(jail):
    _, rec, _ = jail()
    allowed = _flag(_agent_argv(rec), "--allowed-tools").split(",")
    # The only non-MCP approval is a path-scoped file-write rule; a bare
    # `Write` (or `Edit`) would reach the RW /tool-cache bind.
    builtins = [t for t in allowed if not t.startswith("mcp__")]
    assert builtins == ["Edit(//scratch/**)"], builtins


def test_report_published_and_exit_code_kept(jail):
    p, rec, final = jail(rc=3)
    assert p.returncode == 3, p.stderr
    assert final.read_text() == "# report\nok\n"
    # Per-call scratch dir is removed on exit.
    assert rec["scratch"] and not Path(rec["scratch"]).exists()
    # The jail never gets a bind of the host-visible report file.
    assert all(not src.startswith(str(final.parent)) for src, _ in rec["binds"])
