"""Live check: no credential value in any process's argv along the launch chain.

argv is world-readable through /proc/<pid>/cmdline (`ps aux`), and the
memguard systemd scope takes its description from it. Until 2026-10-11
run-agent.sh passed every tool key as `bwrap --setenv KEY value`, and agent
sessions that ran `ps aux` captured live keys.

This drives the real chain on this host, minus the VM:

  server._dial_agent      real: secrets resolved from env, sent on ssh stdin
  -> ssh                  fake: runs the remote command locally under a
                          clean login-style env, as sshd would
  -> bash -c _GUEST_SCRIPT -> scripts/run-agent.sh           real
  -> systemd-run --user --scope + memguard shim              real if available
  -> bwrap                REAL bubblewrap, behind a thin front that maps the
                          guest-only paths and swaps the agent for a probe
  -> probe (jail pid 1)   dumps its own environ, then blocks

Every /proc/*/cmdline on the host is scanned for per-run random dummy
values throughout the launch and while the probe blocks. The probe's
environ proves the keys still reach the jail. Skipped where unprivileged
bwrap cannot build a jail (CI runners); tests/test_run_agent_jail.py holds
the same argv invariant hermetically.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_AGENT = REPO_ROOT / "scripts" / "run-agent.sh"
UUID = "fedcba9876543210fedcba9876543210"

TOOL_KEYS = (
    "EXA_API_KEY", "TAVILY_API_KEY",
    "EUIPO_CLIENT_ID", "EUIPO_CLIENT_SECRET",
    "EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET",
    "TRADERA_APP_ID", "TRADERA_APP_KEY",
)


def _bwrap_usable() -> str | None:
    real = shutil.which("bwrap")
    if not real:
        return None
    r = subprocess.run(
        [real, "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid",
         "--", "/bin/sh", "-c", "true"],
        capture_output=True, timeout=10,
    )
    return real if r.returncode == 0 else None


REAL_BWRAP = _bwrap_usable()
pytestmark = pytest.mark.skipif(
    REAL_BWRAP is None, reason="unprivileged bubblewrap unavailable here"
)

# Jail pid 1. /proc/1/environ is exactly the env bwrap exec'd it with.
PROBE = (
    "cat /proc/1/environ > /scratch/env.bin && : > /scratch/ready && "
    "i=0; while [ ! -e /scratch/stop ] && [ $i -lt 1200 ]; do sleep 0.05; i=$((i+1)); done"
)

BWRAP_FRONT = r'''#!@PYTHON@
# Stands in for bwrap on the guest PATH. Hands the REAL bwrap the same
# env/namespace flags it was given; only remaps paths that exist in the
# guest but not on this host, and swaps the agent for the probe.
import json, os, sys
argv, out, i = sys.argv[1:], [], 0
agent_dir = "@AGENT_DIR@"
while i < len(argv):
    a = argv[i]
    if a == "--":
        out += ["--", "/bin/sh", "-c", @PROBE@]
        break
    if a == "--ro-bind":
        src = argv[i + 1].replace("/workspace/agent", agent_dir, 1)
        out += ["--ro-bind-try", src, argv[i + 2]]
        i += 3
        continue
    if a == "--bind" and argv[i + 2] == "/scratch":
        json.dump({"scratch": argv[i + 1]}, open("@NOTE@", "w"))
    out.append(a)
    i += 1
os.execv("@REAL_BWRAP@", ["bwrap"] + out)
'''

FAKE_SSH = r'''#!/usr/bin/env bash
# sshd runs the remote command with the login shell under a fresh session
# env. Only the run-agent.sh path is remapped onto this checkout.
cmd="${@: -1}"
cmd="${cmd//\/workspace\/scripts\/run-agent.sh/@RUN_AGENT@}"
exec env -i HOME="@HOME@" PATH="@GUEST_PATH@" LANG=C.UTF-8 \
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
  DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
  RESEARCH_REPORTS_DIR="@REPORTS@" \
  bash -c "$cmd"
'''


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def _scan_cmdlines(needles: dict[str, bytes]) -> tuple[set[str], int]:
    """Names whose value appears in any process's argv, and how many live
    processes carried the chain's own marker (proves the scan saw it)."""
    leaked: set[str] = set()
    seen_chain = 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                cmd = f.read()
        except OSError:
            continue
        if UUID.encode() in cmd:
            seen_chain += 1
        for name, val in needles.items():
            if val in cmd:
                leaked.add(name)
    return leaked, seen_chain


@pytest.fixture
def chain(tmp_path, monkeypatch):
    from mcp_server import server

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    note = tmp_path / "scratch.json"
    guest_path = f"{bin_dir}:/run/current-system/sw/bin:{os.environ.get('PATH', '')}"

    _write_exec(bin_dir / "bwrap", BWRAP_FRONT
                .replace("@PYTHON@", sys.executable)
                .replace("@AGENT_DIR@", str(REPO_ROOT / "agent"))
                .replace("@PROBE@", json.dumps(PROBE))
                .replace("@NOTE@", str(note))
                .replace("@REAL_BWRAP@", REAL_BWRAP))
    _write_exec(bin_dir / "ssh", FAKE_SSH
                .replace("@RUN_AGENT@", str(RUN_AGENT))
                .replace("@HOME@", str(tmp_path))
                .replace("@GUEST_PATH@", guest_path)
                .replace("@REPORTS@", str(reports)))
    # Codex path: `command -v codex` gate, and the copy of the guest's
    # /workspace/agent/codex-config.toml.
    _write_exec(bin_dir / "codex", "#!/bin/sh\nexit 99\n")
    _write_exec(bin_dir / "cp", "#!/usr/bin/env bash\n"
                'args=("${@/#\\/workspace\\/agent/' + str(REPO_ROOT / "agent") + '}")\n'
                f'exec {shutil.which("cp")} "${{args[@]}}"\n')

    # Fresh random values per run: never real keys, and unique enough that
    # a hit anywhere in /proc can only come from this chain.
    dummies = {k: f"dummy-{k.lower()}-{secrets.token_hex(12)}" for k in TOOL_KEYS}
    dummies["CLAUDE_CODE_OAUTH_TOKEN"] = f"dummy-claude-{secrets.token_hex(12)}"
    codex_token = f"dummy-codex-{secrets.token_hex(12)}"
    codex_auth = tmp_path / "codex-auth.json"
    codex_auth.write_text(json.dumps({"tokens": {"access_token": codex_token}}))
    codex_auth.chmod(0o600)

    for k, v in dummies.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("RESEARCH_SSH_KEY", str(tmp_path / "no-key"))
    monkeypatch.setenv("RESEARCH_SSH_KNOWN_HOSTS", str(tmp_path / "kh" / "known_hosts"))
    monkeypatch.delenv("RESEARCH_MEM_MAX", raising=False)
    monkeypatch.setattr(server, "_CLAUDE_CREDENTIALS_PATH", tmp_path / "absent.json")
    monkeypatch.setattr(server, "_CODEX_AUTH_PATH", codex_auth)
    monkeypatch.setattr(server, "_ACTIVITY_FILE", tmp_path / "active")
    monkeypatch.setattr(server, "_SSH_RETRIES", 0)
    server.SECRETS_CACHE.clear()

    def run(provider: str):
        needles = {k: v.encode() for k, v in dummies.items()}
        needles["CODEX_AUTH_TOKEN"] = codex_token.encode()
        result: dict = {}

        def dial():
            result["rc"], result["out"] = server._dial_agent(
                "argv probe", UUID, "normal", provider=provider)

        t = threading.Thread(target=dial, daemon=True)
        t.start()
        leaked: set[str] = set()
        seen = 0
        scratch = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and t.is_alive():
            hit, n = _scan_cmdlines(needles)
            leaked |= hit
            seen = max(seen, n)
            if scratch is None and note.exists():
                scratch = Path(json.loads(note.read_text())["scratch"])
            if scratch is not None and (scratch / "ready").exists():
                break
            time.sleep(0.005)
        assert scratch is not None and (scratch / "ready").exists(), result
        # Steady state, with the whole chain alive and the probe blocking.
        hit, n = _scan_cmdlines(needles)
        leaked |= hit
        seen = max(seen, n)
        scope = subprocess.run(
            ["systemctl", "--user", "show", "-p", "Description",
             f"research-{UUID}.scope"],
            capture_output=True, timeout=10,
        ).stdout
        scope_leaks = {k for k, v in needles.items() if v in scope}
        raw = (scratch / "env.bin").read_bytes()
        jail_env = dict(
            e.split("=", 1) for e in raw.decode().split("\0") if "=" in e
        )
        (scratch / "stop").touch()
        t.join(timeout=30)
        assert not t.is_alive(), "chain did not exit after the probe was released"
        return {
            "rc": result.get("rc"), "out": result.get("out", ""),
            "leaked": leaked, "seen": seen, "scope": scope,
            "scope_leaks": scope_leaks, "jail_env": jail_env,
            "dummies": dummies,
        }

    return run


@pytest.mark.parametrize("provider", ["claude", "codex"])
def test_no_credential_in_any_argv_and_keys_reach_jail(chain, provider):
    r = chain(provider)
    assert r["rc"] == 0, r["out"]
    # The scan really saw the chain (run-agent.sh, bwrap, ... carry the uuid).
    assert r["seen"] >= 2, "cmdline scan never saw the launch chain"
    assert r["leaked"] == set(), (
        f"credential values visible in /proc/*/cmdline: {sorted(r['leaked'])}")
    assert r["scope_leaks"] == set(), (
        f"credential values in the memguard scope description: {sorted(r['scope_leaks'])}")

    env, dummies = r["jail_env"], r["dummies"]
    for k in TOOL_KEYS:
        assert env.get(k) == dummies[k], f"{k} did not reach the jail"
    if provider == "claude":
        assert env.get("CLAUDE_CODE_OAUTH_TOKEN") == dummies["CLAUDE_CODE_OAUTH_TOKEN"]
    else:
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in env
        assert env.get("CODEX_HOME") == "/home/agent/.codex"
    assert "CODEX_AUTH_JSON" not in env
    assert env.get("HOME") == "/home/agent"
    assert env.get("RESEARCH_RUN_ID") == UUID
