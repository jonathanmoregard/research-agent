# research-agent

Isolated web-research subsystem for Claude Code. The host session has no exa/tavily access; it calls a single MCP tool, the call is forwarded over ssh into a long-running microvm (qemu+KVM), the microvm spawns a fresh bubblewrap jail per call, and the resulting report is scanned before the host can read it.

## Interface

One MCP tool, exposed to the host Claude session:

```
research(prompt: str) -> { status: "done" | "error", report_path: str, error?: str }
```

The main session writes nothing about web access itself — it just calls this and reports the path back to the user.

## Architecture

```
host Claude session
        |
        | MCP call: research(prompt, depth)
        v
mcp_server/server.py                 (host process)
        |
        | ssh -i agenix:research-agent-host-key -p 2223 agent@127.0.0.1
        v
research-agent microvm               (qemu+KVM, hot)
   - virtiofs RO  /workspace
   - virtiofs RW  /out
   - nftables egress allowlist (anthropic, exa, tavily only)
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
injection-scanner                    (host-side, after ssh returns)
        |
        | pass  -> reports/<uuid>.md, return wrapped report
        | fail  -> reports/_quarantine/<uuid>.md, return error
        v
host Claude session receives result
```

### Per-call isolation

- microVM is **hot** (no per-call boot cost). KVM-isolated kernel separates the agent from the host.
- Each call runs inside a **fresh bubblewrap jail** with tmpfs `$HOME` and tmpfs `/tmp`. No config, history, cache, or scratch persists between calls.
- Writable destination is **one pre-created file** in `/out/<uuid>.md` (virtiofs bind mount of host `reports/`). The agent cannot write anywhere else.

### Trust boundaries

| Layer | Secrets | Web | Writable paths |
|-------|---------|-----|----------------|
| Host Claude (main) | none | **none** | repo, user files |
| MCP server (host) | reads prompt, no keys | none | `reports/` only |
| microVM (long-running) | exa/tavily keys via per-call ssh stdin only | yes, via MCPs only | VM FS (in-memory) |
| Per-call bwrap jail | inherits env | yes | `/scratch/<uuid>.md` only |
| Scanner | none | none | `reports/_quarantine/` |

## Status

- [x] Repo skeleton
- [x] MCP server (`ssh` into the hot microvm)
- [x] microvm.nix host module (qemu+KVM, virtiofs shares, declarative nftables) — replaces Docker
- [x] Per-call bubblewrap jail inside the microvm
- [x] Regex + LLM-honeypot scanner (injection-scanner package) — pre-delivery scan on every report
- [x] End-to-end smoke test round-trips cleanly (`status:done` with agent-written report)
- [x] Network egress allowlist (api.anthropic.com, exa.ai, tavily.com only; declarative nftables)
- [x] Secrets in agenix (NixOS) — never on disk inside the VM, never in static env
- [x] Host `~/.claude.json` cleanup — exa + tavily removed; `research-agent` MCP is the only web tool in the main session
- [ ] External egress proxy container (route outbound through squid/envoy so
      the research-agent itself doesn't hold `NET_ADMIN`)
- [ ] Tier-2 secret isolation (separate systemd user for the MCP server so
      even a compromised main session running as `jonathan` can't read the
      research-agent service account's keyring)

## Directory layout

```
mcp_server/     # host-side MCP server (ssh-driven)
agent/          # guest-side CLAUDE.md + .mcp.json (exa, tavily)
scripts/        # run-agent.sh — bwrap invocation per call (runs inside the microvm)
reports/        # post-scan output (gitignored; virtiofs-shared into the microvm at /out)
```

NixOS module declaring the microvm lives in
`modules/nixos/research-agent-microvm.nix` in the system nixos-config
repo.

## Credits

Per-call bubblewrap jail pattern inspired by
[trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer).
Container outer boundary swapped for a qemu+KVM microvm via
[astro/microvm.nix](https://github.com/astro/microvm.nix).
