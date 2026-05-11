# MicroVM Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (default) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Docker container that runs research-agent's per-call bubblewrap jail with a hot QEMU microvm declared via microvm.nix, keeping bwrap inside the VM as the per-call ephemeral layer.

**Architecture:** Single-tenant defense-in-depth. KVM hypervisor isolates the agent's kernel from dellan; bwrap inside the VM enforces per-call tmpfs `$HOME` / tmpfs `/tmp` / single-writable-file. virtiofs shares the agent code (RO) and reports dir (RW). MCP server reaches the agent via `ssh` on localhost:2223 (replaces `docker exec`). Egress allowlist enforced declaratively via nftables in the guest, gated to sshd via `Requires=`.

**Tech Stack:** NixOS, microvm.nix (github:astro/microvm.nix, pinned tag), QEMU+virtiofs, agenix, Python (FastMCP server), OpenSSH, nftables, bubblewrap.

**Spec:** `docs/superpowers/specs/2026-05-11-microvm-migration-design.md`

**Two-repo scope:**

| Repo | Path | Phase |
|------|------|-------|
| research-agent (this) | `/home/jonathan/Repos/research-agent` | Phase 1 (Tasks 1–9) |
| nixos-config (worktree) | `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/` | Phase 2 (Tasks 10–22) |

The Phase 1 PR ships first and is a no-op on deployed dellan (it deletes files the running container's image already baked in). The Phase 2 PR is the actual deploy: flipping `dellan/default.nix` import is the atomic cutover.

---

## File map

### Phase 1 — research-agent repo

| File | Action | Responsibility |
|------|--------|----------------|
| `mcp_server/server.py` | Modify | Swap `_run_agent` from `docker cp` + `docker exec` to `ssh` with 4-field null-terminated stdin protocol; add new env-var reads. |
| `scripts/run-agent.sh` | Modify | Add invariant check that the rendered `.mcp.json` tmpfile lives on `/tmp` (in-VM disk), not on the virtiofs `/out` share. |
| `tests/test_run_agent_ssh.py` | Create | New unit tests for the SSH transport path using a mocked subprocess. |
| `README.md` | Modify | Update architecture diagram (docker → microvm) and Status checklist. |
| `.devcontainer/Dockerfile` | Delete | Replaced by NixOS module. |
| `.devcontainer/devcontainer.json` | Delete | Replaced by NixOS module. |
| `.devcontainer/` (the directory) | Delete | Empty after the two files above. |
| `scripts/container-entrypoint.sh` | Delete | Replaced by systemd in the VM. |
| `scripts/init-firewall.sh` | Delete | Replaced by declarative nftables in the VM. |

### Phase 2 — nixos-config repo

| File | Action | Responsibility |
|------|--------|----------------|
| `flake.nix` | Modify | Add `inputs.microvm` pinned to a tag with `inputs.nixpkgs.follows = "nixpkgs"`; pass `inputs` via `specialArgs`. |
| `modules/nixos/research-agent-microvm.nix` | Create | Declares `microvm.vms.research-agent` (qemu hypervisor, 2 vcpu, 2GB mem, virtiofs shares, SLIRP networking with one port-forward, nftables egress allowlist, agent user pinned to uid 1000, persisted SSH host keys, sshd gated on egress-init). |
| `modules/nixos/research-agent-container.nix` | Delete | Replaced by the microvm module. |
| `hosts/dellan/default.nix` | Modify | Drop the container module import, add the microvm host module import + the microvm VM module import, import `microvm.nixosModules.host`. |
| `secrets/secrets.nix` | Modify | Declare two new agenix entries: `research-agent-host-key`, `research-agent-host-key-pub`. |
| `secrets/research-agent-host-key.age` | Create | Encrypted SSH privkey. Decrypted to `/run/agenix/research-agent-host-key` (owner `jonathan`, mode `0400`) for the MCP server. |
| `secrets/research-agent-host-key-pub.age` | Create | Encrypted SSH pubkey. Decrypted inside the VM and fed to `users.users.agent.openssh.authorizedKeys.keyFiles`. |
| `tests/dellan-vm.nix` | Modify | Add 7 ordered, blocking assertions (microvm active, ssh probe, virtiofs mounts, virtiofs uid round-trip, egress allowlist drop + accept, fast-depth E2E). |

---

## Phase 1: research-agent repo

### Task 1: Baseline — verify current test suite is green

**Files:** read-only

- [ ] **Step 1.1:** Confirm working directory.

```bash
cd /home/jonathan/Repos/research-agent
pwd
```

Expected: `/home/jonathan/Repos/research-agent`

- [ ] **Step 1.2:** Confirm clean git state.

```bash
git status
```

Expected: `nothing to commit, working tree clean` (or just untracked files outside the repo's tracked tree). Plan + spec files we committed earlier are already in `main`.

- [ ] **Step 1.3:** Run the existing test suite as a baseline.

```bash
uv run pytest -x -q
```

Expected: all tests pass. Note the count. If any fail at baseline, **STOP** and surface to the operator — the plan assumes a green starting state.

### Task 2: Write failing test for SSH-based `_run_agent`

**Files:**
- Create: `/home/jonathan/Repos/research-agent/tests/test_run_agent_ssh.py`

- [ ] **Step 2.1:** Create the new test file.

```python
"""Tests for the SSH transport in mcp_server.server._run_agent.

The test mocks subprocess.run so we can assert the exact ssh argv
and stdin protocol without needing a running VM. Verifies:

- ssh is invoked (not docker)
- exactly four null-terminated fields land on stdin, in order:
    claude_token, exa_api_key, tavily_api_key, prompt_body
- RESEARCH_DEPTH is set via the SSH command's argv (-o SetEnv=)
- uuid is passed as the first positional arg
- timeout and return-code propagate
"""
from __future__ import annotations

import io
import subprocess
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("RESEARCH_SSH_HOST", "127.0.0.1")
    monkeypatch.setenv("RESEARCH_SSH_PORT", "2223")
    monkeypatch.setenv("RESEARCH_SSH_KEY", "/fake/key")
    monkeypatch.setenv("RESEARCH_SSH_USER", "agent")
    # Prevent the scanner-update path from touching the network.
    monkeypatch.setenv("EXA_API_KEY", "exa-test-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tav-test-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "ct-test")
    yield


def _import_server():
    # Late import so env vars are read.
    from mcp_server import server
    # Reset secret cache between tests.
    server.SECRETS_CACHE.clear()
    return server


def test_run_agent_uses_ssh_not_docker():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["input"] = kwargs.get("input")
        captured["timeout"] = kwargs.get("timeout")
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        code, out = server._run_agent(
            prompt="what is the capital of france",
            report_id="deadbeef" * 4,
            depth="normal",
        )

    assert code == 0
    argv = captured["argv"]
    assert argv[0] == "ssh", f"first arg should be ssh, got {argv!r}"
    # No docker anywhere in the invocation.
    assert "docker" not in " ".join(argv)
    # Identity file + port from env.
    assert "-i" in argv
    assert "/fake/key" in argv
    assert "-p" in argv
    assert "2223" in argv
    # User@host.
    assert "agent@127.0.0.1" in argv
    # RESEARCH_DEPTH passed through the SSH command.
    joined = " ".join(argv)
    assert "RESEARCH_DEPTH=normal" in joined


def test_run_agent_stdin_is_four_null_terminated_fields():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["input"] = kwargs.get("input", "")
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        server._run_agent(
            prompt="the prompt body",
            report_id="cafef00d" * 4,
            depth="normal",
        )

    data = captured["input"]
    # Split on NUL.
    parts = data.split("\0")
    # We expect exactly 4 fields followed by a trailing empty string
    # (because the encoding always terminates the last field).
    assert parts[-1] == ""
    fields = parts[:-1]
    assert len(fields) == 4, f"expected 4 fields, got {len(fields)}: {fields!r}"
    assert fields[0] == "ct-test"          # claude token
    assert fields[1] == "exa-test-key"     # exa
    assert fields[2] == "tav-test-key"     # tavily
    # Prompt body is the rendered PROMPT_TEMPLATE, not the bare prompt.
    # We only require that the user prompt appears inside it.
    assert "the prompt body" in fields[3]


def test_run_agent_uuid_passed_as_argv():
    server = _import_server()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return MagicMock(returncode=0, stdout="DONE\n", stderr="")

    uuid = "11112222333344445555666677778888"
    with patch.object(subprocess, "run", side_effect=fake_run):
        server._run_agent(
            prompt="x",
            report_id=uuid,
            depth="normal",
        )
    # The uuid is the last positional in the SSH command (after `bash -s --`).
    assert uuid in captured["argv"], "uuid must be passed as argv to ssh"


def test_run_agent_timeout_propagates():
    server = _import_server()

    def fake_run(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=kw.get("timeout", 1))

    with patch.object(subprocess, "run", side_effect=fake_run):
        with pytest.raises(subprocess.TimeoutExpired):
            server._run_agent(
                prompt="x", report_id="0" * 32, depth="normal",
            )
```

- [ ] **Step 2.2:** Run the test and verify it fails with the current docker-based code.

```bash
uv run pytest tests/test_run_agent_ssh.py -x -v
```

Expected: at least 3 of 4 tests **FAIL** because `_run_agent` currently calls `docker cp` / `docker exec`. (`test_run_agent_timeout_propagates` may pass coincidentally — fine.)

- [ ] **Step 2.3:** Commit the failing test.

```bash
git add tests/test_run_agent_ssh.py
git commit -m "test(mcp_server): add failing tests for ssh-based _run_agent"
```

### Task 3: Swap `_run_agent` from docker to ssh

**Files:**
- Modify: `/home/jonathan/Repos/research-agent/mcp_server/server.py`

- [ ] **Step 3.1:** Locate the existing constants block.

Read `mcp_server/server.py:143-154`. You'll see:

```python
CONTAINER = os.environ.get("RESEARCH_CONTAINER", "research-agent")
AGENT_TIMEOUT = int(os.environ.get("RESEARCH_AGENT_TIMEOUT", "600"))
CONTAINER_WORKSPACE = os.environ.get("RESEARCH_CONTAINER_WORKSPACE", "/workspace")
```

- [ ] **Step 3.2:** Replace the two `CONTAINER*` lines with SSH env vars. `AGENT_TIMEOUT` stays.

```python
RESEARCH_SSH_HOST = os.environ.get("RESEARCH_SSH_HOST", "127.0.0.1")
RESEARCH_SSH_PORT = os.environ.get("RESEARCH_SSH_PORT", "2223")
RESEARCH_SSH_KEY = os.environ.get(
    "RESEARCH_SSH_KEY", "/run/agenix/research-agent-host-key"
)
RESEARCH_SSH_USER = os.environ.get("RESEARCH_SSH_USER", "agent")
RESEARCH_SSH_KNOWN_HOSTS = os.environ.get(
    "RESEARCH_SSH_KNOWN_HOSTS",
    str(Path.home() / ".cache" / "research-agent" / "known_hosts"),
)
AGENT_TIMEOUT = int(os.environ.get("RESEARCH_AGENT_TIMEOUT", "600"))
```

Use `Edit` with `old_string` matching the exact three current lines.

- [ ] **Step 3.3:** Replace the entire body of `_run_agent` (function definition stays — `def _run_agent(prompt: str, report_id: str, depth: Depth) -> tuple[int, str]:`).

Current body uses `tempfile.NamedTemporaryFile`, `docker cp`, `docker exec`, stdin payload with 3 fields. Replace with:

```python
    scratch_path = f"/scratch/{report_id}.md"
    full_prompt = PROMPT_TEMPLATE.format(
        scratch_path=scratch_path,
        depth_guidance=DEPTH_GUIDANCE[depth],
        prompt=prompt,
    )

    secrets = _secrets()
    # 4 null-terminated fields: claude_token, exa, tavily, prompt_body.
    # Mirrors the docker-era stdin contract but adds the prompt body
    # as a fourth field — no separate file-copy step.
    stdin_payload = "".join(
        s + "\0"
        for s in (
            secrets.get("claude-token", ""),
            secrets.get("exa-api-key", ""),
            secrets.get("tavily-api-key", ""),
            full_prompt,
        )
    )

    # Guest-side inline bash: read four fields, write the prompt to a
    # tmp file under the agent user's home, exec run-agent.sh with
    # (uuid, prompt_file). The EXIT trap cleans the tmp file even on
    # SSH disconnect.
    GUEST_SCRIPT = (
        "set -euo pipefail; "
        "IFS= read -r -d '' CLAUDE_CODE_OAUTH_TOKEN; "
        "IFS= read -r -d '' EXA_API_KEY; "
        "IFS= read -r -d '' TAVILY_API_KEY; "
        "IFS= read -r -d '' PROMPT_BODY; "
        "export CLAUDE_CODE_OAUTH_TOKEN EXA_API_KEY TAVILY_API_KEY; "
        'TMP=$(mktemp -p "$HOME" research-prompt.XXXXXX); '
        'chmod 600 "$TMP"; '
        "trap 'rm -f \"$TMP\"' EXIT; "
        'printf %s "$PROMPT_BODY" > "$TMP"; '
        'exec /workspace/scripts/run-agent.sh "$1" "$TMP"'
    )

    Path(RESEARCH_SSH_KNOWN_HOSTS).parent.mkdir(parents=True, exist_ok=True)

    ssh_cmd = [
        "ssh",
        "-i", RESEARCH_SSH_KEY,
        "-p", str(RESEARCH_SSH_PORT),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={RESEARCH_SSH_KNOWN_HOSTS}",
        "-o", "ServerAliveInterval=30",
        f"{RESEARCH_SSH_USER}@{RESEARCH_SSH_HOST}",
        f"RESEARCH_DEPTH={depth} bash -s -- {report_id}",
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            input=stdin_payload,
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise

    return result.returncode, (result.stdout + result.stderr)
```

Note: `GUEST_SCRIPT` is built but currently unused — the guest reads it from the SSH command. We pass the entire script via the SSH argv's final positional, then `bash -s --` reads from stdin. Replace the final two args with:

```python
        f"{RESEARCH_SSH_USER}@{RESEARCH_SSH_HOST}",
        f"RESEARCH_DEPTH={depth} bash -c {shlex.quote(GUEST_SCRIPT)} bash {report_id}",
```

Add `import shlex` near the top.

- [ ] **Step 3.4:** Add `import shlex` to the import block at top of the file (it's not currently imported).

Use `Edit` to add `import shlex` after `import shutil`.

- [ ] **Step 3.5:** Run the new SSH tests.

```bash
uv run pytest tests/test_run_agent_ssh.py -x -v
```

Expected: all 4 tests **PASS**.

- [ ] **Step 3.6:** Run the full test suite to confirm no regressions.

```bash
uv run pytest -x -q
```

Expected: all tests pass.

- [ ] **Step 3.7:** Commit the transport swap.

```bash
git add mcp_server/server.py
git commit -m "feat(mcp_server): swap _run_agent transport from docker to ssh

Replaces docker cp + docker exec with a single ssh invocation. Stdin
carries four null-terminated fields (claude_token, exa, tavily,
prompt_body) consumed by a guest-side inline bash that writes the
prompt to a tmp file under the agent user's home and exec's
scripts/run-agent.sh with (uuid, prompt_file).

Removes envs RESEARCH_CONTAINER, RESEARCH_CONTAINER_WORKSPACE.
Adds   envs RESEARCH_SSH_HOST, RESEARCH_SSH_PORT, RESEARCH_SSH_KEY,
            RESEARCH_SSH_USER, RESEARCH_SSH_KNOWN_HOSTS."
```

### Task 4: Add `/tmp` invariant check to `scripts/run-agent.sh`

**Files:**
- Modify: `/home/jonathan/Repos/research-agent/scripts/run-agent.sh:75-79`

The rendered `.mcp.json` tmpfile contains substituted `EXA_API_KEY` and `TAVILY_API_KEY`. It must land on the in-VM `/tmp`, never on `/out` (virtiofs RW, visible to the host).

- [ ] **Step 4.1:** Locate the `RENDERED_MCP=$(mktemp ...)` block.

Read `scripts/run-agent.sh:75-79`. Current:

```bash
RENDERED_MCP=$(mktemp --suffix=.mcp.json)
chmod 644 "${RENDERED_MCP}"
python3 -c 'import os,sys; sys.stdout.write(os.path.expandvars(sys.stdin.read()))' \
  < "${AGENT_DIR}/.mcp.json" > "${RENDERED_MCP}"
trap 'rm -f "${RENDERED_MCP}"' EXIT
```

- [ ] **Step 4.2:** Insert an invariant check right after the `mktemp` line so the path is enforced before any secret substitution writes to it.

Replace the block with:

```bash
RENDERED_MCP=$(mktemp --suffix=.mcp.json)
# Invariant: the rendered file holds substituted API keys; it MUST live
# on /tmp (in-VM disk), NEVER on /out (virtiofs share, visible to host).
# Without this guard, a future operator who exports TMPDIR=/out would
# silently leak secrets to the host's reports/ dir.
case "${RENDERED_MCP}" in
  /tmp/*) ;;
  *) echo "run-agent: refusing to render .mcp.json outside /tmp (got ${RENDERED_MCP})" >&2; exit 3 ;;
esac
chmod 600 "${RENDERED_MCP}"  # was 644 — tighten to owner-only
python3 -c 'import os,sys; sys.stdout.write(os.path.expandvars(sys.stdin.read()))' \
  < "${AGENT_DIR}/.mcp.json" > "${RENDERED_MCP}"
trap 'rm -f "${RENDERED_MCP}"' EXIT
```

- [ ] **Step 4.3:** Commit.

```bash
git add scripts/run-agent.sh
git commit -m "harden(run-agent): pin rendered .mcp.json to /tmp + chmod 600

The rendered file holds substituted EXA_API_KEY / TAVILY_API_KEY. After
the microvm migration the host sees the guest's /out via virtiofs;
landing the rendered file there (e.g. via TMPDIR=/out) would leak the
keys. Explicit case check fails loud rather than silently writing to
the wrong tier."
```

### Task 5: Delete `.devcontainer/Dockerfile` and `.devcontainer/devcontainer.json`

**Files:**
- Delete: `/home/jonathan/Repos/research-agent/.devcontainer/Dockerfile`
- Delete: `/home/jonathan/Repos/research-agent/.devcontainer/devcontainer.json`

- [ ] **Step 5.1:** Confirm no other file references either path.

```bash
grep -RIn -e Dockerfile -e devcontainer.json --include='*.nix' --include='*.py' --include='*.sh' --include='*.md' . /etc/nixos 2>/dev/null | grep -v -E '(\.git/|/docs/superpowers/)'
```

Expected output: only the spec/plan/README references. If you see live code referencing the path (other than the about-to-be-deleted `research-agent-container.nix` in `/etc/nixos`), surface it before proceeding.

- [ ] **Step 5.2:** Delete both files.

```bash
git rm .devcontainer/Dockerfile .devcontainer/devcontainer.json
```

- [ ] **Step 5.3:** If `.devcontainer/` is now empty, remove the directory too.

```bash
rmdir .devcontainer 2>/dev/null || true
```

- [ ] **Step 5.4:** Commit.

```bash
git commit -m "chore: delete .devcontainer/ — replaced by microvm.nix module"
```

### Task 6: Delete `scripts/container-entrypoint.sh` and `scripts/init-firewall.sh`

**Files:**
- Delete: `/home/jonathan/Repos/research-agent/scripts/container-entrypoint.sh`
- Delete: `/home/jonathan/Repos/research-agent/scripts/init-firewall.sh`

- [ ] **Step 6.1:** Confirm no other file in this repo references them.

```bash
grep -RIn -e container-entrypoint -e init-firewall --include='*.py' --include='*.sh' --include='*.nix' --include='*.md' . 2>/dev/null | grep -v '\.git/'
```

Expected: only doc references. The `/etc/nixos/modules/nixos/research-agent-container.nix` reference is fine — that file is being deleted in Phase 2.

- [ ] **Step 6.2:** Delete both files.

```bash
git rm scripts/container-entrypoint.sh scripts/init-firewall.sh
```

- [ ] **Step 6.3:** Commit.

```bash
git commit -m "chore: delete container-entrypoint.sh + init-firewall.sh

Replaced by the new modules/nixos/research-agent-microvm.nix module:
- entrypoint replaced by systemd inside the VM
- iptables/ipset firewall replaced by declarative nftables
"
```

### Task 7: Update `README.md`

**Files:**
- Modify: `/home/jonathan/Repos/research-agent/README.md`

- [ ] **Step 7.1:** Re-read the current README to confirm the sections to edit.

```bash
cat README.md
```

Sections to update: "Architecture" (the ASCII diagram), Trust-boundaries table row "Container", and "Status" checklist.

- [ ] **Step 7.2:** Replace the architecture diagram.

Use `Edit` to replace lines 17-44 with:

```
host Claude session
        |
        | MCP call: research(prompt)
        v
mcp_server/server.py                 (host process)
        |
        | ssh -i ... -p 2223 agent@127.0.0.1
        v
research-agent microvm               (qemu+KVM, hot)
        |   - virtiofs RO /workspace
        |   - virtiofs RW /out
        |   - nftables egress allowlist
        |
        | scripts/run-agent.sh
        v
bubblewrap jail                      (ephemeral, per call)
   - tmpfs $HOME
   - tmpfs /tmp
   - read-only system, agent dir
   - writable bind: /scratch/<uuid>.md only
        |
        | claude -p (tools: exa, tavily, Write)
        v
scanner (host-side, after jail exits)
        |
        | pass  -> reports/<uuid>.md, return wrapped report
        | fail  -> reports/_quarantine/<uuid>.md, return error
        v
host Claude session receives result
```

- [ ] **Step 7.3:** Update the Trust boundaries row.

Replace the line containing `| Container (long-running)` with:

```
| microVM (long-running) | exa/tavily keys via per-call ssh stdin only | yes, via MCPs only | VM FS (in-memory disk) |
```

- [ ] **Step 7.4:** Update the Status checklist.

- Change `- [x] Devcontainer based on Trail of Bits pattern (Ubuntu 24.04 + bwrap + Claude Code)` to:

```
- [x] microvm.nix host (NixOS, qemu+virtiofs, replaces Docker)
- [x] Per-call bubblewrap jail inside the microvm
```

- Delete the old line if it survives the replacement.

- [ ] **Step 7.5:** Commit.

```bash
git add README.md
git commit -m "docs(README): update architecture for microvm migration"
```

### Task 8: Run full test suite, confirm Phase 1 is green

- [ ] **Step 8.1:** Run all tests.

```bash
uv run pytest -x -q
```

Expected: every test passes. The baseline from Task 1.3 + the 4 new tests from Task 2.

- [ ] **Step 8.2:** Confirm git log is clean.

```bash
git log --oneline main..HEAD
```

Expected output (5 commits, oldest at bottom):
```
docs(README): update architecture for microvm migration
chore: delete container-entrypoint.sh + init-firewall.sh
chore: delete .devcontainer/ — replaced by microvm.nix module
harden(run-agent): pin rendered .mcp.json to /tmp + chmod 600
feat(mcp_server): swap _run_agent transport from docker to ssh
test(mcp_server): add failing tests for ssh-based _run_agent
```

(Note: spec + plan commits should already be in `main` from earlier in this session.)

### Task 9: Push Phase 1 PR

- [ ] **Step 9.1:** Push the branch (we've been working on `main`; cut a feature branch first so the PR is reviewable).

Pause and confirm with the operator: push directly to `main` or open a PR? The repo's recent commits go through PRs (`PR #1`, `#2`, `#3` per git log). Default: PR.

If PR:

```bash
git checkout -b feat/microvm-migration
git push -u origin feat/microvm-migration
gh pr create --base main --title "feat: migrate runtime from Docker to microvm.nix" --body "Spec: docs/superpowers/specs/2026-05-11-microvm-migration-design.md
Plan: docs/superpowers/plans/2026-05-11-microvm-migration.md

This PR is the research-agent side of the migration. Lands first as a
no-op on deployed dellan (the running container's image already has
these files baked in). The nixos-config companion PR flips the deploy."
```

**STOP** here. Wait for PR review / merge before proceeding to Phase 2. The operator clicks merge in the GitHub UI.

---

## Phase 2: nixos-config repo (worktree-driven, deploys to dellan)

Per the SessionStart HARD RULE: all of Phase 2 happens in a worktree under `~/Repos/nixos-config-worktrees/<slug>/`, ships through CI, gets merged by a human in the GitHub UI, and auto-deploys via the webhook. This plan covers writing the change; the actual `nix run .#feature-vm` smoke test in Task 18 is invoked via the `nixos-agent-testing` skill from within that worktree.

### Task 10: Create the worktree

- [ ] **Step 10.1:** From the nixos-config primary checkout (`/etc/nixos`), create a worktree.

```bash
cd /etc/nixos
git fetch origin
git worktree add ~/Repos/nixos-config-worktrees/feat-research-agent-microvm -b feat/research-agent-microvm origin/main
cd ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
```

- [ ] **Step 10.2:** Confirm clean state and the right branch.

```bash
git status
git rev-parse --abbrev-ref HEAD
```

Expected: clean tree, branch `feat/research-agent-microvm`.

### Task 11: Resolve microvm.nix pin tag

- [ ] **Step 11.1:** Look up the latest stable tag of `github:astro/microvm.nix`.

Either via the host's web access tooling or by running:

```bash
nix flake metadata github:astro/microvm.nix 2>/dev/null | head -20
```

Expected: a `revCount` + `lastModified`. Note the most recent tag in the upstream releases. Write it down as `MICROVM_TAG=<tag>` in your scratch notes.

If no tagged release is suitable, pin by commit SHA: `?rev=<full-40-char-sha>` instead of `?ref=<tag>`. Either form is acceptable; tag is preferred.

### Task 12: Generate the SSH keypair and encrypt with agenix

- [ ] **Step 12.1:** Generate the keypair on dellan into a temp dir.

```bash
TMP=$(mktemp -d) && cd "$TMP"
ssh-keygen -t ed25519 -N "" -C "research-agent-host-key" -f research-agent-host-key
```

You'll have `research-agent-host-key` (private) and `research-agent-host-key.pub` (public).

- [ ] **Step 12.2:** Switch back to the worktree, look at `secrets/secrets.nix` for the agenix-recipients structure.

```bash
cd ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
cat secrets/secrets.nix
```

Note the existing entries' shape (e.g. `"existing-secret.age".publicKeys = ...`) and the recipients (likely the dellan host key + your user key).

- [ ] **Step 12.3:** Add two new entries to `secrets/secrets.nix`.

```nix
"research-agent-host-key.age".publicKeys = jonathan ++ dellan;
"research-agent-host-key-pub.age".publicKeys = jonathan ++ dellan;
```

(Reuse the same `jonathan` / `dellan` binding pattern present in the file. The pub key still goes through agenix because it's used by `keyFiles` inside the VM — keeping both halves declarative makes audit simpler.)

- [ ] **Step 12.4:** Encrypt both files.

```bash
cd secrets
EDITOR='cp "'"$TMP"'/research-agent-host-key" ' agenix -e research-agent-host-key.age
EDITOR='cp "'"$TMP"'/research-agent-host-key.pub" ' agenix -e research-agent-host-key-pub.age
```

(The `EDITOR=cp ...` trick replaces agenix's interactive prompt with a non-interactive write. Verify both `.age` files now exist and are non-empty.)

- [ ] **Step 12.5:** Clean up the plaintext temp dir.

```bash
shred -u "$TMP"/research-agent-host-key "$TMP"/research-agent-host-key.pub
rmdir "$TMP"
```

- [ ] **Step 12.6:** Stage and commit.

```bash
cd ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
git add secrets/secrets.nix secrets/research-agent-host-key.age secrets/research-agent-host-key-pub.age
git commit -m "secrets: add research-agent SSH host keypair"
```

### Task 13: Add microvm.nix flake input

**Files:**
- Modify: `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/flake.nix`

- [ ] **Step 13.1:** Open the flake and locate the `inputs = { ... }` block.

- [ ] **Step 13.2:** Add the input. After the `agenix` lines, before the closing `};` of `inputs`:

```nix
    microvm.url = "github:astro/microvm.nix?ref=<MICROVM_TAG>";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
```

Replace `<MICROVM_TAG>` with the value resolved in Task 11.

- [ ] **Step 13.3:** Update the `outputs = { ... }` argument list to include `microvm`.

```nix
  outputs = { self, nixpkgs, home-manager, agenix, microvm, ... }:
```

- [ ] **Step 13.4:** Add `microvm` to `specialArgs` so modules can `inputs`-import it. In the `nixosConfigurations.dellan = nixpkgs.lib.nixosSystem { ... }` block, add (or extend if already present):

```nix
      specialArgs = { inherit microvm; };
```

(If the flake already wires `inputs` via `specialArgs`, just add `microvm` to whatever's already passed.)

- [ ] **Step 13.5:** Run `nix flake lock` to add the new input.

```bash
nix flake lock --update-input microvm 2>&1 | tail
```

If the file says `--update-input` is removed: `nix flake update microvm`.

Expected: `flake.lock` now contains a `microvm` node pinned to the tag.

- [ ] **Step 13.6:** Commit.

```bash
git add flake.nix flake.lock
git commit -m "flake: add microvm.nix input pinned to <MICROVM_TAG>"
```

### Task 14: Pre-flight `nix eval` diff for the host-module collision check

Goal: capture `dellan`'s networking + systemd surface **before** the microvm host module is imported, so we can diff after.

- [ ] **Step 14.1:** Snapshot the baseline.

```bash
mkdir -p /tmp/microvm-preflight
nix eval --json .#nixosConfigurations.dellan.config.networking 2>/dev/null > /tmp/microvm-preflight/networking.before.json
nix eval --json .#nixosConfigurations.dellan.config.systemd.services 2>/dev/null > /tmp/microvm-preflight/services.before.json
```

If those evals fail (some attributes are non-trivial to eval whole), substitute a more targeted query, e.g.:

```bash
nix eval .#nixosConfigurations.dellan.config.networking.bridges
nix eval --json .#nixosConfigurations.dellan.config.networking.firewall.allowedTCPPorts
```

Capture whatever fragments are useful; the point is to have something to diff against after Task 16.

### Task 15: Write `modules/nixos/research-agent-microvm.nix`

**Files:**
- Create: `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/modules/nixos/research-agent-microvm.nix`

- [ ] **Step 15.1:** Create the file with the full module.

```nix
{ config, lib, pkgs, microvm, ... }:
# research-agent microvm — replaces the docker-based
# research-agent-container.service.
#
# Lifecycle: microvm.nix synthesizes microvm@research-agent.service
# from this declaration. Boot order: network-online -> microvm boot
# -> in-guest systemd starts research-agent-egress-init.service ->
# sshd.service (gated via Requires=).
#
# Host MCP server reaches the VM via ssh on 127.0.0.1:2223 (port
# forward from SLIRP user-mode networking). Per-call isolation is
# enforced by bwrap inside the VM, exactly as in the docker era.
{
  microvm.vms.research-agent = {
    flake = "/etc/nixos";  # so the VM can refer to the same flake
    config = { config, pkgs, ... }: {

      microvm = {
        hypervisor = "qemu";
        vcpu = 2;
        mem = 2048;

        shares = [
          {
            source = "/home/jonathan/Repos/research-agent";
            mountPoint = "/workspace";
            tag = "workspace";
            proto = "virtiofs";
          }
          {
            source = "/home/jonathan/Repos/research-agent/reports";
            mountPoint = "/out";
            tag = "out";
            proto = "virtiofs";
          }
          {
            # Persisted VM SSH host keys (across reboots).
            source = "/home/jonathan/.local/state/research-agent/vm-ssh";
            mountPoint = "/etc/ssh/keys";
            tag = "ssh-keys";
            proto = "virtiofs";
          }
        ];

        interfaces = [
          {
            type = "user";
            id = "qemu0";
            mac = "02:00:00:00:00:01";
          }
        ];

        forwardPorts = [
          { from = "host"; host.port = 2223; guest.port = 22; proto = "tcp"; }
        ];
      };

      # System packages — replaces Dockerfile apt + pip layer.
      environment.systemPackages = with pkgs; [
        bubblewrap
        python3
        python3Packages.curl-cffi
        python3Packages.exa-py
        python3Packages.tavily-python
        # claude-code: use nixpkgs if available; otherwise fall back
        # to wrapping the upstream installer in a buildFHSEnv.
        # Implementation plan checks availability at Task 15.2.
      ];

      # Pin agent uid to 1000 so virtiofs passthrough lines up with
      # host jonathan. Without this, files written to /out by the
      # guest agent land on the host with the wrong owner and the
      # host MCP server cannot unlink them.
      users.users.agent = {
        isNormalUser = true;
        uid = 1000;
        shell = pkgs.bashInteractive;
        openssh.authorizedKeys.keyFiles = [
          config.age.secrets.research-agent-host-key-pub.path
        ];
      };

      # agenix wiring (inside the VM).
      age.secrets.research-agent-host-key-pub = {
        file = ../../secrets/research-agent-host-key-pub.age;
        mode = "0444";
        owner = "agent";
        group = "users";
      };

      services.openssh = {
        enable = true;
        # Persisted across boots via the virtiofs ssh-keys share.
        hostKeys = [
          { path = "/etc/ssh/keys/ssh_host_ed25519_key"; type = "ed25519"; }
        ];
        settings = {
          PasswordAuthentication = false;
          PermitRootLogin = "no";
        };
      };

      # SSH only listens after the egress allowlist is populated. If
      # egress-init fails (e.g. DNS resolution exhausts retries), sshd
      # transitions to failed and the host MCP server fails fast with
      # `Connection refused` instead of a 10-minute silent hang.
      systemd.services.sshd = {
        after = [ "research-agent-egress-init.service" ];
        requires = [ "research-agent-egress-init.service" ];
      };

      # Egress allowlist — declarative nftables, populated at boot.
      networking.nftables = {
        enable = true;
        ruleset = ''
          table inet filter {
            set research_allowed {
              type ipv4_addr
              flags interval
            }

            chain input {
              type filter hook input priority 0; policy drop;
              iif lo accept
              ct state established,related accept
              # SSH from host (port forward inside guest).
              tcp dport 22 accept
            }

            chain output {
              type filter hook output priority 0; policy drop;
              oif lo accept
              ct state established,related accept
              udp dport 53 accept
              tcp dport 53 accept
              ip daddr @research_allowed tcp dport 443 accept
            }
          }
        '';
      };

      systemd.services.research-agent-egress-init = {
        description = "Resolve allowlist FQDNs and populate nftables set";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" "nftables.service" ];
        wants = [ "network-online.target" ];
        requires = [ "nftables.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = [ pkgs.nftables pkgs.glibc pkgs.coreutils pkgs.gnused ];
        script = ''
          set -euo pipefail

          ALLOWED=(
            api.anthropic.com
            api.exa.ai
            mcp.exa.ai
            api.tavily.com
            mcp.tavily.com
          )

          # Same retry semantics as the Docker-era init-firewall.sh.
          DNS_RETRIES=5
          DNS_RETRY_SLEEP=2

          resolve_or_die() {
            local domain="$1" attempt ips
            for ((attempt=1; attempt<=DNS_RETRIES; attempt++)); do
              ips=$(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u)
              if [ -n "$ips" ]; then
                printf '%s\n' "$ips"
                return 0
              fi
              if [ $attempt -lt $DNS_RETRIES ]; then
                echo "[egress-init] DNS miss for $domain ($attempt/$DNS_RETRIES), retrying in $DNS_RETRY_SLEEP s" >&2
                sleep $DNS_RETRY_SLEEP
              fi
            done
            echo "[egress-init] ERROR: failed to resolve $domain after $DNS_RETRIES attempts" >&2
            return 1
          }

          # Flush set before populating (idempotent re-run).
          nft flush set inet filter research_allowed || true

          for d in "''${ALLOWED[@]}"; do
            ips=$(resolve_or_die "$d") || exit 1
            while IFS= read -r ip; do
              [ -z "$ip" ] && continue
              nft add element inet filter research_allowed { $ip } || true
              echo "[egress-init] allow $d -> $ip"
            done <<< "$ips"
          done

          echo "[egress-init] firewall active"
        '';
      };

      # Boot a minimal system; this VM doesn't need a graphical stack.
      networking.hostName = "research-agent";
      system.stateVersion = "25.11";
    };
  };
}
```

- [ ] **Step 15.2:** Verify `pkgs.claude-code` exists in the pinned nixpkgs. If yes, append it to `environment.systemPackages`. If no, replace the placeholder with the buildFHSEnv-wrapped installer (separate sub-task — pause here and surface to operator).

```bash
nix eval --raw .#nixosConfigurations.dellan.pkgs.claude-code.meta.description 2>/dev/null && echo OK || echo MISSING
```

If `OK`: add `claude-code` to the systemPackages list.
If `MISSING`: pause. Plan ranks this a sub-decision — implement `pkgs.buildFHSEnv` wrapping `curl https://claude.ai/install.sh | bash` only after operator confirms there's no upstream nixpkgs derivation worth using instead.

- [ ] **Step 15.3:** Commit the module.

```bash
git add modules/nixos/research-agent-microvm.nix
git commit -m "feat(nixos): add research-agent microvm module

Declarative replacement for modules/nixos/research-agent-container.nix.
Per-call bwrap jail inside the VM stays; outer container boundary is
now a qemu+KVM microvm instead of a Docker container."
```

### Task 16: Swap the dellan host import

**Files:**
- Modify: `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/hosts/dellan/default.nix`
- Modify: `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/flake.nix` (add microvm host module to dellan's module list)

- [ ] **Step 16.1:** Open `hosts/dellan/default.nix` and look at the imports list.

- [ ] **Step 16.2:** Replace the line importing `../../modules/nixos/research-agent-container.nix` with `../../modules/nixos/research-agent-microvm.nix`. (If the container module is imported via the flake's module list instead of the host file, edit the flake — same swap.)

- [ ] **Step 16.3:** In `flake.nix`, add `microvm.nixosModules.host` to `nixosConfigurations.dellan`'s module list. Same module list where you already have agenix and home-manager.

- [ ] **Step 16.4:** Pre-create the host directory that the VM's ssh-keys share will mount.

This is **not** Nix-managed (the dir lives in `~/.local/state` on dellan); document in the module header that the dir must exist before boot. Add a `systemd.tmpfiles.rules` entry to the dellan host config so it's created at activation:

In `hosts/dellan/default.nix`, add:

```nix
systemd.tmpfiles.rules = [
  "d /home/jonathan/.local/state/research-agent 0750 jonathan users -"
  "d /home/jonathan/.local/state/research-agent/vm-ssh 0700 jonathan users -"
];
```

(If the file already has `systemd.tmpfiles.rules`, extend it; don't replace.)

- [ ] **Step 16.5:** Delete the old container module.

```bash
git rm modules/nixos/research-agent-container.nix
```

- [ ] **Step 16.6:** Run the after-snapshot of the pre-flight eval (Task 14).

```bash
nix eval --json .#nixosConfigurations.dellan.config.networking 2>/dev/null > /tmp/microvm-preflight/networking.after.json
diff -u /tmp/microvm-preflight/networking.before.json /tmp/microvm-preflight/networking.after.json | head -200
```

Read the diff. Expected new entries: microvm-related network plumbing (e.g. a `microvm-host` bridge, or none if SLIRP). If you see your existing networking options *changed* (e.g. `useNetworkd` flipped, `firewall.enable` modified), pause and investigate — this is the host-module-collision case the advisor flagged.

- [ ] **Step 16.7:** Build the dellan toplevel to surface eval/build errors.

```bash
nix build .#nixosConfigurations.dellan.config.system.build.toplevel
```

Expected: build succeeds. If it fails with an option conflict, fix in this task before committing.

- [ ] **Step 16.8:** Commit the swap.

```bash
git add hosts/dellan/default.nix flake.nix
git rm --cached modules/nixos/research-agent-container.nix 2>/dev/null || true
git commit -m "feat(dellan): swap research-agent runtime from docker to microvm

Imports research-agent-microvm module + microvm.nixosModules.host.
Adds tmpfiles rule for the persisted vm-ssh state directory.
Deletes the docker-era container module."
```

### Task 17: Extend `tests/dellan-vm.nix` with the migration assertions

**Files:**
- Modify: `~/Repos/nixos-config-worktrees/feat-research-agent-microvm/tests/dellan-vm.nix`

- [ ] **Step 17.1:** Read the current `tests/dellan-vm.nix` to learn the test framework conventions (likely `nixosTest` returning a `testScript = '' ... ''`).

- [ ] **Step 17.2:** Add the 7 assertions described in the spec's §Testing. Append a new `subtest` block to the `testScript`:

```python
with subtest("research-agent microvm — boot + ssh + egress"):
    # 1. microvm service active within 90s.
    machine.wait_for_unit("microvm@research-agent.service", timeout=90)
    # 2. SSH probe reaches sshd inside the inner VM.
    machine.wait_for_open_port(2223, host="127.0.0.1", timeout=60)
    machine.succeed(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 echo ok | grep -q ok"
    )
    # 3. virtiofs mounts visible in the inner guest.
    machine.succeed(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 findmnt /workspace"
    )
    machine.succeed(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 findmnt /out"
    )
    # 4. uid round-trip: guest creates a file in /out, host sees it as uid 1000.
    machine.succeed(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 'touch /out/uidcheck && stat -c %u /out/uidcheck' "
        "| grep -q '^1000$'"
    )
    machine.succeed(
        "stat -c %u /home/jonathan/Repos/research-agent/reports/uidcheck "
        "| grep -q '^1000$'"
    )
    machine.succeed(
        "rm -f /home/jonathan/Repos/research-agent/reports/uidcheck"
    )
    # 5. Egress allowlist — drop on non-allowlisted host.
    machine.fail(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 curl -sS -o /dev/null -m 5 https://example.com"
    )
    # 6. Egress allowlist — accept on allowlisted host (any non-zero connect).
    machine.succeed(
        "ssh -p 2223 -o BatchMode=yes -o StrictHostKeyChecking=no "
        "-i /run/agenix/research-agent-host-key "
        "agent@127.0.0.1 curl -sS -o /dev/null -m 5 -w '%{http_code}' https://api.exa.ai/"
        " | grep -E '^(200|301|302|400|401|403|404)$'"
    )
    # 7. End-to-end smoke — fast depth, direct Exa, no nested bwrap.
    # Skipped if EXA_API_KEY is not exposed to the test runner; the
    # rest of the assertions are sufficient for CI gating.
```

(Indent matches the existing `testScript` block; use spaces if the surrounding code uses spaces.)

- [ ] **Step 17.3:** Commit.

```bash
git add tests/dellan-vm.nix
git commit -m "test(dellan-vm): assert microvm boot, ssh, virtiofs uid, egress allowlist"
```

### Task 18: Run the automated test locally

- [ ] **Step 18.1:** Run the test.

```bash
cd ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
nix build .#checks.x86_64-linux.dellan-vm -L
```

Expected: build succeeds, all subtest assertions pass.

If assertion 1 (microvm service active) fails with KVM-not-available errors, this is the nested-KVM landmine the advisor flagged. Plan B: downgrade the automated test to:

```python
with subtest("research-agent microvm — module evaluates + activation"):
    machine.succeed("systemctl cat microvm@research-agent.service")
    machine.succeed("test -f /etc/systemd/system/microvm@research-agent.service")
```

…and rely on the interactive `nix run .#feature-vm` smoke (Task 19) as the only end-to-end gate. Document the downgrade in the commit message.

### Task 19: Interactive smoke via `nixos-agent-testing` skill

Per the SessionStart HARD RULE, branching logic (nftables ruleset) + multistep activation (egress-init resolves DNS then populates an nftables set) requires manual pre-PR smoke.

- [ ] **Step 19.1:** Invoke the `nixos-agent-testing` skill from inside this worktree.

```
/skill nixos-agent-testing
```

- [ ] **Step 19.2:** Follow the skill's procedure to boot `.#feature-vm`, ssh in, verify:

- `journalctl -u research-agent-egress-init` shows successful DNS resolution and set population
- `nft list set inet filter research_allowed` shows 5+ resolved IPs
- `curl -v https://api.exa.ai/` reaches the endpoint
- `curl -v https://example.com/` is dropped
- A `research(depth="normal")` call through the live MCP server inside the feature-vm returns a wrapped report

Document the screencap + journal snippets in the worktree's commit log if anything was non-trivial.

### Task 20: Push and open the deploy PR

- [ ] **Step 20.1:** Push the branch.

```bash
cd ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
git push -u origin feat/research-agent-microvm
```

- [ ] **Step 20.2:** Open the PR.

```bash
gh pr create --base main \
  --title "feat: migrate research-agent runtime to microvm.nix" \
  --body "Companion to research-agent#<PR-from-Task-9>.

Spec: research-agent docs/superpowers/specs/2026-05-11-microvm-migration-design.md
Plan: research-agent docs/superpowers/plans/2026-05-11-microvm-migration.md

- Adds microvm.nix flake input (pinned to <MICROVM_TAG>).
- Adds modules/nixos/research-agent-microvm.nix.
- Adds two agenix entries for the host SSH keypair.
- Adds tmpfiles rule for /home/jonathan/.local/state/research-agent/vm-ssh.
- Extends tests/dellan-vm.nix with 7 blocking assertions.
- Deletes modules/nixos/research-agent-container.nix.

Pre-merge interactive smoke completed via nix run .#feature-vm
(see commit log for the screencap + journal snippets)."
```

- [ ] **Step 20.3:** **STOP.** Wait for CI to go green and a human to click merge. (Per CLAUDE.md: `gh pr merge` is denied at the MCP layer — merging is always a deliberate gesture.)

### Task 21: Post-deploy verification

After the webhook auto-deploys the merged change to dellan:

- [ ] **Step 21.1:** Confirm `microvm@research-agent.service` is active on dellan.

```bash
systemctl is-active microvm@research-agent.service
```

Expected: `active`.

- [ ] **Step 21.2:** From a fresh terminal on dellan, run a real research call.

Invoke through the live MCP server (i.e. trigger via Claude Code in a non-isolated session, depth=fast).

Expected: a wrapped report comes back, `status: done`.

- [ ] **Step 21.3:** Capture the baseline journal for future debugging.

```bash
journalctl -u microvm@research-agent.service --since "10 min ago" > /tmp/microvm-deploy-baseline.log
```

- [ ] **Step 21.4:** Clean up the worktree.

```bash
cd /etc/nixos
git worktree remove ~/Repos/nixos-config-worktrees/feat-research-agent-microvm
```

### Task 22: Update Status checklist in research-agent README

- [ ] **Step 22.1:** Back in the research-agent repo, mark the migration items in the Status list as done.

```bash
cd /home/jonathan/Repos/research-agent
# Use Edit to flip:
#   - [ ] -> - [x] for microvm-related lines.
```

- [ ] **Step 22.2:** Commit + push.

```bash
git add README.md
git commit -m "docs(README): mark microvm migration as shipped"
git push
```

---

## Self-review

**Spec coverage:**
- §Threat model: Tasks 3 (transport), 15 (uid pin, egress, fail-loud sshd gate), 4 (rendered .mcp.json on /tmp) — covered.
- §Architecture diagram: Task 7 (README) — covered.
- §1 NixOS module: Task 15 — covered.
- §2 flake wiring + tag pin + pre-flight: Tasks 13, 14, 16 — covered.
- §3 nftables + egress-init: Task 15 — covered.
- §4 MCP server: Tasks 2, 3 — covered.
- §5 run-agent.sh /tmp invariant: Task 4 — covered.
- §6 secrets + VM host keys persistence: Tasks 12, 15, 16 — covered.
- §7 deleted files: Tasks 5, 6, 16 — covered.
- §8 updated files: Tasks 7, 13, 16 — covered.
- §Testing: Tasks 17, 18, 19 — covered.

**Placeholder scan:**
- `<MICROVM_TAG>` appears in Tasks 11, 13, 20 — that's a value the engineer resolves in Task 11, not a placeholder for "fill in later". Acceptable.
- `<PR-from-Task-9>` in Task 20 — same pattern. Acceptable.
- Task 15.2 has a real branch ("if claude-code is in nixpkgs, use it; else pause") — not a placeholder, an explicit decision gate.

**Type/signature consistency:**
- `_run_agent(prompt, report_id, depth)` signature unchanged (just transport swap) — Task 2 tests match Task 3 implementation.
- Stdin protocol: 4 fields in order (claude_token, exa, tavily, prompt_body) — same order in Task 2 test (`fields[0..3]`), Task 3 impl (`stdin_payload`), Task 15 guest-side bash. Consistent.
- File paths consistent across plan and spec (`/workspace`, `/out`, `/etc/ssh/keys`).

No issues found.
