# Design: Migrate research-agent runtime from Docker to microvm.nix

**Date:** 2026-05-11
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
- `networking.nftables` with declarative ruleset implementing the
  egress allowlist (see §3).

### 2. flake.nix wiring

- Add `inputs.microvm.url = "github:astro/microvm.nix"` with
  `inputs.microvm.inputs.nixpkgs.follows = "nixpkgs"`.
- Import `microvm.nixosModules.host` into the `dellan` host.
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
    prompt file is piped via the SSH stdin alongside the three
    secret tokens — still null-terminated, still parsed by the inline
    bash on the guest before exec into `run-agent.sh`.
  - Replace `docker exec -i CONTAINER bash -c '…'` with
    `ssh -i $RESEARCH_SSH_KEY -p $RESEARCH_SSH_PORT
         -o BatchMode=yes
         -o StrictHostKeyChecking=accept-new
         -o UserKnownHostsFile=~/.cache/research-agent/known_hosts
         -o ServerAliveInterval=30
         $RESEARCH_SSH_USER@$RESEARCH_SSH_HOST
         RESEARCH_DEPTH=$depth bash -s -- "$uuid"`.
    Inline bash on the guest reads four null-terminated fields from
    stdin (prompt file path payload, then three secrets), writes the
    prompt to a tmp file under the agent user's home, then `exec
    /workspace/scripts/run-agent.sh "$uuid" "$tmpfile"`.
  - `docker exec rm -f` cleanup → `ssh ... rm -f` cleanup.
- Error handling unchanged: `subprocess.TimeoutExpired`, non-zero exit,
  empty report, `_log_agent_failure`, all still apply.

### 5. `scripts/run-agent.sh`

Unchanged. Paths `/workspace` and `/out` map identically to the
virtiofs mount points. bwrap invocation, allowlist tools, model
selection — all stay.

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

VM SSH host keys: generated declaratively via
`services.openssh.hostKeys`. Persisted on a small virtiofs RW share
(`~/.cache/research-agent/vm-ssh-host-keys` → `/etc/ssh`-keyfiles) so
the host's `known_hosts` pin survives VM reboot. Alternative
(accepted-on-first-use, regenerated each boot) is simpler but means
the MCP server has to use `StrictHostKeyChecking=accept-new` every
boot — acceptable for v1; revisit if it ever generates a useful audit
signal.

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

Add assertions:

1. `systemctl is-active microvm@research-agent.service` returns 0.
2. SSH probe: `ssh -p 2223 -o BatchMode=yes -o ConnectTimeout=5
   -o StrictHostKeyChecking=no agent@127.0.0.1 echo ok` returns `ok`.
3. Egress allowlist active: from inside the VM,
   `curl -sS -o /dev/null -w "%{http_code}" https://example.com
   --max-time 5` fails (connect refused or timeout). Same probe
   against `https://api.exa.ai` returns HTTP 200/403/4xx (any
   non-zero connect).
4. virtiofs mounts present:
   `findmnt /workspace` and `findmnt /out` both return 0.
5. End-to-end smoke: invoke `research()` via the MCP wrapper inside
   the test VM with `depth=fast` (direct Exa, no agent — fastest
   gate). Confirm a wrapped report comes back. Optional: `depth=normal`
   gated behind a longer timeout for the full round-trip.

This is the `dellan-vm` test that runs in GitHub Actions on PR.

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

1. nixos-config worktree: add microvm.nix flake input + host module
   import; write the new `research-agent-microvm.nix` module
   end-to-end; extend `tests/dellan-vm.nix`. Verify via
   `nix build .#checks.x86_64-linux.dellan-vm`.
2. Interactive smoke via `nix run .#feature-vm`.
3. research-agent repo: swap `_run_agent` to SSH transport behind an
   env flag so the same MCP server can talk to either docker or
   microvm during cutover. CI verifies the SSH path.
4. nixos-config PR: flip the host's import from
   `research-agent-container.nix` to `research-agent-microvm.nix`.
   Merge → webhook deploy.
5. Companion PR in research-agent: delete `.devcontainer/`,
   `scripts/container-entrypoint.sh`, `scripts/init-firewall.sh`,
   the docker-fallback branch in `_run_agent`. Update README.

## Open questions

None for design — all decisions in this doc are explicit. The
implementation plan (next step, via `writing-plans` skill) will
break each numbered item in §"Implementation order" into concrete
file diffs.
