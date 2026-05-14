# Design: Migrate research-agent runtime from Docker to microvm.nix

**Date:** 2026-05-11
**Status:** revised after Opus advisor pass (2026-05-11). Key changes:
guest `agent` uid pinned to 1000 (§1), SSH stdin protocol fully
specified (§4), VM host keys persisted via virtiofs share (§6),
egress-init failure gates sshd (§3), nested-KVM gotcha called out
with plan B (§Testing), atomic cutover replaces dual-mode env flag
(§Implementation order).
**Repos affected:** `research-agent`, `nixos-config` (`/etc/nixos`)
**Pipeline:** every change to `nixos-config` goes through the
worktree → PR → CI (`dellan-vm`) → merge → webhook auto-deploy flow.
The `research-agent` repo change ships as a same-day companion PR; the
deploy gate is the nixos-config PR.

## Why

`modules/nixos/docker.nix` already carries a `TODO(nixos-migration):
replace Docker with Firecracker via microvm.nix` and `pending_for_human.md`
lists microvm.nix runner isolation as an outstanding research
recommendation. The research-agent's per-call security model currently
relies on:

1. A Docker container (`research-agent-container.service`) running with
   `--cap-add=NET_ADMIN`, `seccomp=unconfined`, `apparmor=unconfined`.
2. A bubblewrap jail inside that container, per call.

Docker's container boundary is namespace + cgroup isolation against a
shared host kernel. A kernel-level container escape (CVE class:
overlayfs / user-namespace / netfilter privilege escalation) defeats it.
A microvm gives the agent its own kernel inside a KVM guest; the same
class of escape no longer reaches dellan's kernel.

We keep bwrap inside the microvm. Defense in depth: hypervisor stops
kernel-class escapes, bwrap stops per-call state leaks (tmpfs `$HOME`,
tmpfs `/tmp`, single writable file) without paying the boot cost of a
per-call VM.

## Threat model boundary

Single tenant (one operator: `jonathan`). No untrusted callers. Threat
is **prompt injection in retrieved web content** coercing the agent
into:

- Writing outside the scratch path (mitigated: bwrap writable bind is
  one pre-created file).
- Exfiltrating secrets via outbound request to an attacker-controlled
  domain (mitigated: nftables egress allowlist).
- Persisting state across calls to chain attacks (mitigated: per-call
  tmpfs jail).
- Escaping the agent runtime to read host files (current: Docker
  kernel boundary; **proposed: KVM hypervisor boundary**).

The migration upgrades the outermost boundary from a shared-kernel
container to a hardware-virtualized KVM guest with its own kernel.

## Non-goals

- LLM scanner upgrade (regex → llm-guard / Haiku layer). Independent;
  already on backlog. Scanner is host-side, untouched by this change.
- External egress proxy container (squid / envoy). Backlog.
- Tier-2 secret isolation (separate systemd user for the MCP server).
  Backlog.
- Removing Docker host-wide from `modules/nixos/docker.nix`. Other
  services may still need it; that audit is a separate PR.

## Architecture

```
host Claude session
        │ MCP call: research(prompt, depth)
        ▼
mcp_server.server                                  (NixOS user service)
        │ ssh -i /run/agenix/research-agent-host-key \
        │     -p 2223 agent@127.0.0.1 \
        │     RESEARCH_DEPTH=<d> scripts/run-agent.sh <uuid>
        ▼
microvm: research-agent                            (hot, qemu microvm)
   - virtiofs RO: /workspace ← ~/Repos/research-agent
   - virtiofs RW: /out       ← ~/Repos/research-agent/reports
   - nftables egress allowlist (anthropic, exa, tavily endpoints)
        │
        │ scripts/run-agent.sh (unchanged) → bwrap jail
        ▼
bubblewrap jail                                    (ephemeral, per call)
   - tmpfs $HOME, tmpfs /tmp, ro system + agent dir
   - writable bind: /scratch/<uuid>.md → virtiofs /out/<uuid>.md
        │ claude -p ... --allowed-tools exa,tavily,Write
        ▼
report at host reports/<uuid>.md
        │
        ▼
mcp_server _safe_read (O_NOFOLLOW) → injection_scanner.intercept
        │ pass → wrap in <untrusted_external_content>, return
        │ fail → reports/_quarantine/<uuid>.md, return error
        ▼
host Claude session
```

## Component breakdown

### 1. NixOS module — `modules/nixos/research-agent-microvm.nix`

Replaces `modules/nixos/research-agent-container.nix`. Declares
`microvm.vms.research-agent` with:

- `hypervisor = "qemu"`, `vcpu = 2`, `mem = 2048`.
- Two virtiofs `shares`:
  - RO `/workspace` ← `/home/jonathan/Repos/research-agent`
  - RW `/out` ← `/home/jonathan/Repos/research-agent/reports`
- One `user`-mode (SLIRP) network interface. No host bridge needed —
  egress is what we want; ingress is one port forward (host:2223 →
  guest:22) for the MCP server's SSH connection.
  - **SLIRP + nftables interaction:** SLIRP serves DNS at `10.0.2.3`
    and rewrites destination IPs for some traffic classes. `dellan-vm`
    must include a **blocking** assertion that, from inside the guest,
    `curl https://api.exa.ai` reaches the endpoint while
    `curl https://example.com` is dropped. If SLIRP NAT shape breaks
    the IP-allowlist semantics, the plan switches to a `tap` interface
    on a host-side bridge with the same nftables policy. Verify first,
    fall back if needed.
- `environment.systemPackages`: `bubblewrap`, `python3`,
  `python3Packages.curl-cffi`, `python3Packages.exa-py`,
  `python3Packages.tavily-python`. Replaces the Dockerfile's
  `apt-get install` + `pip3 install --break-system-packages`.
- Claude Code CLI: prefer `pkgs.claude-code` if present in the
  nixpkgs pin; otherwise wrap the upstream installer
  (`curl https://claude.ai/install.sh | bash`) in `pkgs.buildFHSEnv`
  or `pkgs.writeShellApplication` activated at first boot. Decision
  finalized in the implementation plan after verifying nixpkgs
  availability.
- `services.openssh.enable = true` with `PasswordAuthentication = false`
  and `PermitRootLogin = "no"`.
- `users.users.agent` (non-root) with `authorizedKeys` from
  `config.age.secrets.research-agent-host-key-pub.path`. Runs
  `scripts/run-agent.sh`.
  - **uid pinned to 1000** to match host `jonathan`. virtiofsd's
    default passthrough exposes host file ownership as-is to the
    guest; matching uids keeps `~/Repos/research-agent/reports`
    writable by `agent` inside the guest **and** still owned by
    `jonathan` from the host's view after the call. Without this
    pin, bwrap's `--unshare-user` mapping (uid 0 → nobody/65534)
    layered on top of a uid-mismatched virtiofs share produces
    `nobody`-owned files in `reports/` that the host MCP server
    cannot unlink. Verified in `dellan-vm`: after a `research()`
    call, `stat reports/<uuid>.md` from the host shows `jonathan`
    ownership.
- `networking.nftables` with declarative ruleset implementing the
  egress allowlist (see §3).

### 2. flake.nix wiring

- Add `inputs.microvm.url = "github:astro/microvm.nix?ref=<TAG>"`
  pinned to a tagged release (resolved at plan time) with
  `inputs.microvm.inputs.nixpkgs.follows = "nixpkgs"`.
  microvm.nix is an active project with breaking changes on `main`
  (option renames in 2024 affected `microvm.shares` schema and
  hypervisor defaults); pinning a tag stops a future
  `nix flake update` from silently breaking the dellan rebuild
  during an unrelated PR.
- Import `microvm.nixosModules.host` into the `dellan` host. **Pre-flight
  gate** in the implementation plan: in a worktree, `nix eval
  .#nixosConfigurations.dellan.config.networking` and
  `.config.systemd.services` **before and after** adding the import
  and diff the resulting JSON. The `host` module touches networking
  (sets up `/var/lib/microvms`, adds `microvm@.service` template,
  may declare a bridge depending on options chosen). If the diff
  surfaces an option-conflict with existing networking, the plan
  decides whether to disable a microvm host sub-option or rework the
  bridge config before merging.
- Import `microvm.nixosModules.microvm` into the VM's module set (per
  microvm.nix convention).
- Pass `inputs` to host modules via the standard
  `specialArgs = { inherit inputs; }` pattern.

### 3. Egress firewall — nftables, declarative

`init-firewall.sh` (imperative iptables + ipset + runtime DNS) is
deleted. Inside the guest:

- `systemd.services.research-agent-egress-init`: oneshot,
  `After = network-online.target`. Resolves the five allowed FQDNs
  using `getent ahostsv4` with the same retry/backoff loop currently
  in `init-firewall.sh` (5 retries, 2s sleep, fail-loud-and-exit on
  total resolution failure). Writes resolved IPs into the nftables set
  `research_allowed` via `nft add element`.
- `networking.nftables.enable = true` with a base ruleset:
  - `set research_allowed { type ipv4_addr; flags interval; }`
  - `chain output { type filter hook output priority 0; policy drop; }`
  - Accept: `oifname "lo"`, `ct state established,related`,
    `udp dport 53`, `tcp dport 53`,
    `tcp dport 443 ip daddr @research_allowed`.

Allowed FQDNs match current `init-firewall.sh`:
`api.anthropic.com`, `api.exa.ai`, `mcp.exa.ai`, `api.tavily.com`,
`mcp.tavily.com`.

**Failure mode = fail-closed at the SSH door.** Declaring
`networking.nftables` brings the base ruleset up at boot (default
drop) regardless of whether the egress-init oneshot populates the
allowlist set. If DNS resolution fails after all retries, an empty
set + default drop means every research call silently times out
inside the VM rather than failing loud at the host MCP server.

To fail loud, the VM's sshd unit gates on egress-init:

```nix
systemd.services.sshd = {
  after = [ "research-agent-egress-init.service" ];
  requires = [ "research-agent-egress-init.service" ];
};
```

`Requires=` (not `Wants=`) means a failed egress-init transitions
sshd to `failed` as well; the host MCP server's SSH attempt fails
fast with `Connection refused`, surfaced as a normal `agent failed`
error. Operators see the failure in `journalctl -u
research-agent-egress-init` on the VM; on the host this looks like a
single failing `research()` call rather than a 10-minute timeout
hang.

### 4. MCP server changes — `mcp_server/server.py`

Diff is localized to `_run_agent` and a small number of env-var reads:

- New env vars:
  - `RESEARCH_SSH_HOST` (default `127.0.0.1`)
  - `RESEARCH_SSH_PORT` (default `2223`)
  - `RESEARCH_SSH_KEY` (default `/run/agenix/research-agent-host-key`)
  - `RESEARCH_SSH_USER` (default `agent`)
- Removed env vars: `RESEARCH_CONTAINER`, `RESEARCH_CONTAINER_WORKSPACE`.
- `_run_agent`:
  - Replace `docker cp` (prompt file) with a single SSH stream. The
    prompt file body is piped via the SSH stdin alongside the three
    secret tokens — still null-terminated, parsed by the inline
    bash on the guest before exec into `run-agent.sh`.
  - Replace `docker exec -i CONTAINER bash -c '…'` with
    `ssh -i $RESEARCH_SSH_KEY -p $RESEARCH_SSH_PORT
         -o BatchMode=yes
         -o StrictHostKeyChecking=yes
         -o UserKnownHostsFile=~/.cache/research-agent/known_hosts
         -o ServerAliveInterval=30
         $RESEARCH_SSH_USER@$RESEARCH_SSH_HOST
         RESEARCH_DEPTH=$depth bash -s -- "$uuid"`.
  - **Stdin protocol — exactly four null-terminated fields, in this
    order:** `claude_token`, `exa_api_key`, `tavily_api_key`,
    `prompt_body`. Guest-side inline bash:

    ```bash
    set -euo pipefail
    IFS= read -r -d '' CLAUDE_CODE_OAUTH_TOKEN
    IFS= read -r -d '' EXA_API_KEY
    IFS= read -r -d '' TAVILY_API_KEY
    IFS= read -r -d '' PROMPT_BODY
    export CLAUDE_CODE_OAUTH_TOKEN EXA_API_KEY TAVILY_API_KEY
    TMP=$(mktemp -p "$HOME" research-prompt.XXXXXX)
    chmod 600 "$TMP"
    trap 'rm -f "$TMP"' EXIT
    printf '%s' "$PROMPT_BODY" > "$TMP"
    exec /workspace/scripts/run-agent.sh "$1" "$TMP"
    ```

    Both argv slots (`$1` = uuid, `$2` = prompt file) are passed to
    `run-agent.sh`; the EXIT trap cleans the tmp file even on SSH
    disconnect.
  - No separate `ssh ... rm -f` cleanup needed — the guest-side trap
    handles it.
- Error handling unchanged: `subprocess.TimeoutExpired`, non-zero exit,
  empty report, `_log_agent_failure`, all still apply.

### 5. `scripts/run-agent.sh`

Unchanged. Paths `/workspace` and `/out` map identically to the
virtiofs mount points. bwrap invocation, allowlist tools, model
selection — all stay.

**Note on the rendered `.mcp.json` tmpfile** (L75–79 of
`scripts/run-agent.sh`): `mktemp` lands in the guest's `/tmp`
(in-VM disk), not on `/out` (virtiofs RW share). This is correct
already — the rendered file contains substituted `EXA_API_KEY` and
`TAVILY_API_KEY` values; landing it on virtiofs would expose the
key fragments to the host's filesystem. The implementation plan
adds an explicit pre-condition check (`[[ "${RENDERED_MCP}" == /tmp/* ]]`)
to make the intent enforceable rather than implicit.

### 6. Secrets — agenix

Three new entries in `/etc/nixos/secrets/secrets.nix`:

| Path | Owner | Mode | Consumer |
|------|-------|------|----------|
| `/run/agenix/research-agent-host-key` | `jonathan` | `0400` | MCP server (host) — SSH private key |
| `/run/agenix/research-agent-host-key-pub` | `root` | `0444` | VM — `users.users.agent.openssh.authorizedKeys.keyFiles` |

API keys (`EXA_API_KEY`, `TAVILY_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`,
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) — **unchanged**. Still loaded by
`/etc/nixos/home/research-agent-mcp.nix` wrapper on the host. Still
piped via stdin into the SSH stream per call. VM never holds them
at rest.

VM SSH host keys: **persisted via a dedicated virtiofs RW share** at
host `~/.local/state/research-agent/vm-ssh/` mounted into the guest
at `/etc/ssh/keys`. `services.openssh.hostKeys` points at that
directory. First boot generates the keys; every subsequent boot
reuses them, so the host's pinned `known_hosts` entry stays valid
across reboots and the MCP server can use `StrictHostKeyChecking=yes`
(fail-closed on key change). The "accept-new + regenerate each boot"
alternative is rejected because the second boot would trigger
`REMOTE HOST IDENTIFICATION HAS CHANGED` and brick `research()`
until an operator manually deletes the known_hosts line.

### 7. Files deleted

Research-agent repo:

- `.devcontainer/Dockerfile`
- `.devcontainer/devcontainer.json`
- `scripts/container-entrypoint.sh`
- `scripts/init-firewall.sh`

NixOS config repo:

- `modules/nixos/research-agent-container.nix`

### 8. Files updated

Research-agent repo:

- `mcp_server/server.py` — docker→ssh swap (§4)
- `README.md` — architecture diagram, status checklist
- `agent/.mcp.json` — unchanged (Python shims paths `/workspace/agent/shims/*`
  still valid)

NixOS config repo:

- `flake.nix` — add microvm input, wire host module (§2)
- `secrets/secrets.nix` — add two new agenix entries (§6)
- `hosts/dellan/default.nix` — import the new microvm module; drop
  `research-agent-container.nix` import; **do not** drop `docker.nix`
  here unless audit confirms no other consumer
- `tests/dellan-vm.nix` — assertions (§9)

## Testing

Migration ships through the nixos-config pipeline.

### Automated — `tests/dellan-vm.nix`

`tests/dellan-vm.nix` runs under the `nixosTest` framework, which
boots the SUT inside QEMU. Running a **second** QEMU microvm inside
the test VM requires nested KVM. GitHub Actions's `ubuntu-latest`
runners with KVM nested-virt expose `/dev/kvm` — already in use by
the existing test suite — so nested microvm boot is feasible there.
On developer machines without nested KVM (e.g. some laptops),
microvm.nix with `hypervisor = "qemu"` can fall back to TCG, accepting
a slower boot. CI is the authoritative gate either way.

Assertions (in order, each blocking):

1. **Module evaluates + builds.** Confirmed implicitly by reaching the
   test phase — failure here means the new module is broken, no
   point running the rest.
2. **`microvm@research-agent.service` becomes active** within the
   test's 90s window. Failure here means the inner VM can't boot
   under nested-KVM-on-TCG conditions; the spec switches plan B
   (downgrade to a build-only check + move end-to-end to interactive
   smoke).
3. **SSH probe:** `ssh -p 2223 -o BatchMode=yes -o ConnectTimeout=5
   -o StrictHostKeyChecking=no agent@127.0.0.1 echo ok` returns `ok`.
4. **virtiofs mounts present in guest:**
   `ssh ... findmnt /workspace` and `ssh ... findmnt /out` both
   return 0.
5. **virtiofs uid round-trip:** create a file in `/out` from the guest
   `agent` user, verify host sees it owned by `jonathan` (uid 1000).
6. **Egress allowlist active.** From inside the guest:
   - `curl -sS -o /dev/null -w "%{http_code}" --max-time 5
     https://example.com` fails (connect refused / timeout). **This
     is a blocking assertion** — SLIRP NAT semantics interacting
     with nftables drop policy is the single biggest risk in the
     migration; if this passes locally and fails on CI (or vice
     versa), implementation pauses for diagnosis before merge.
   - `curl -sS -o /dev/null --max-time 5 https://api.exa.ai`
     completes the TCP handshake (HTTP 200/403/4xx all acceptable).
7. **End-to-end smoke:** invoke `research(prompt, depth="fast")` via
   the MCP wrapper inside the test VM. `fast` is the direct-Exa path
   (no agent, no nested bwrap inside the inner VM) — fastest, most
   reliable end-to-end signal. A `depth="normal"` smoke gated behind
   a longer test timeout is **opt-in** (skipped on CI by default,
   runnable locally); the inner bwrap + claude CLI inside a nested
   QEMU is a lot of moving parts to gate every PR on.

If assertion 2 fails on CI even after debugging, plan B: the
automated test downgrades to "module evaluates + activation script
of `microvm@research-agent.service` exists in dellan toplevel". The
full end-to-end then lives only in the interactive `nix run
.#feature-vm` smoke (still pre-PR per the SessionStart HARD RULE).

### Interactive — `nixos-agent-testing` skill

Per the SessionStart HARD RULE: branching logic in the nftables
ruleset + multistep activation script (egress-init resolves DNS then
populates the nftables set) require a manual pre-PR smoke. Use
`nix run .#feature-vm` from the worktree, SSH into the feature VM,
verify:

- `journalctl -u research-agent-egress-init` shows successful DNS
  resolution and ipset population.
- `nft list set inet filter research_allowed` shows the five
  resolved IPs.
- `curl -v https://api.exa.ai/` reaches the endpoint.
- `curl -v https://example.com/` is dropped.
- A `research()` call through the deployed MCP server inside the
  feature VM returns a wrapped report with `status: done`.

### Rollback

Single-commit revert of the nixos-config PR. The webhook deploys
the revert. `research-agent-container.nix` returns; the research-agent
repo's deleted files are restored from the companion PR's revert.

## Implementation order (sketch — full plan via writing-plans skill)

Atomic cutover (no env-flag dual-mode). The NixOS rebuild boundary
already gives us an atomic deploy + rollback; emulating a Docker-era
feature flag inside the MCP server adds branches with no upside.

1. **research-agent repo PR** (lands first, no deploy impact): swap
   `_run_agent` to SSH transport (the only transport), update
   stdin protocol to 4 fields, update README + architecture diagram,
   delete `.devcontainer/Dockerfile`,
   `.devcontainer/devcontainer.json`,
   `scripts/container-entrypoint.sh`,
   `scripts/init-firewall.sh`. CI (host-side pytest) verifies the
   SSH transport with a mocked SSH endpoint. The old
   `research-agent-container.service` still works because nothing on
   the deployed `dellan` references the deleted files yet — the
   docker module builds the image from a git checkout, but the
   deployed image already exists from the previous boot.
2. **nixos-config worktree**: pin `inputs.microvm`, run the
   `nix eval` pre-flight diff on `nixosConfigurations.dellan`, write
   `modules/nixos/research-agent-microvm.nix`, add the two new
   agenix entries, extend `tests/dellan-vm.nix`. Verify locally
   via `nix build .#checks.x86_64-linux.dellan-vm`.
3. **Interactive smoke** via `nix run .#feature-vm` (mandatory per
   SessionStart HARD RULE — module contains branching logic and a
   multistep activation script).
4. **nixos-config PR**: flip the dellan host's import from
   `research-agent-container.nix` to `research-agent-microvm.nix`,
   delete `research-agent-container.nix`. CI runs the extended
   `dellan-vm` test. Merge → webhook auto-deploys to dellan.
5. **Post-deploy verification**: from a fresh terminal on dellan,
   run a `research(depth="normal")` end-to-end via the live MCP
   server. Confirm wrapped report. Capture
   `journalctl -u microvm@research-agent.service` baseline.

## Open questions

None for design — all decisions in this doc are explicit. The
implementation plan (next step, via `writing-plans` skill) will
break each numbered item in §"Implementation order" into concrete
file diffs.
