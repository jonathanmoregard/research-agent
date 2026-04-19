# research-agent

Isolated web-research subsystem for Claude Code. The host session has no exa/tavily access; it calls a single MCP tool, the call is forwarded into a long-running dev container, the container spawns a fresh bubblewrap jail per call, and the resulting report is scanned before the host can read it.

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
        | MCP call: research(prompt)
        v
mcp_server/server.py                 (host process)
        |
        | docker exec
        v
research-agent container             (long-running, hot)
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
scanner/regex.py                     (host-side, after jail exits)
        |
        | pass  -> reports/<uuid>.md, return path
        | fail  -> reports/_quarantine/<uuid>.md, return error
        v
host Claude session receives result
```

### Per-call isolation

- Container is **hot** (no startup cost).
- Each call runs inside a **fresh bubblewrap jail** with tmpfs `$HOME` and tmpfs `/tmp`. No config, history, cache, or scratch persists between calls.
- Writable destination is **one pre-created file** in `/out/<uuid>.md` (bind mount of host `reports/`). The agent cannot write anywhere else.

### Trust boundaries

| Layer | Secrets | Web | Writable paths |
|-------|---------|-----|----------------|
| Host Claude (main) | none | **none** | repo, user files |
| MCP server (host) | reads prompt, no keys | none | `reports/` only |
| Container (long-running) | exa/tavily keys in env | yes, via MCPs only | container FS |
| Per-call bwrap jail | inherits env | yes | `/scratch/<uuid>.md` only |
| Scanner | none | none | `reports/_quarantine/` |

## Status

- [x] Repo skeleton
- [x] MCP server (`docker exec` into hot container)
- [x] Per-call bubblewrap wrapper script
- [x] Regex scanner seed (passing tests) — includes token-shape leak patterns
- [x] Devcontainer based on Trail of Bits pattern (Ubuntu 24.04 + bwrap + Claude Code)
- [x] End-to-end smoke test round-trips cleanly (`status:done` with agent-written report)
- [x] Network egress allowlist (api.anthropic.com, exa.ai, tavily.com only; default DROP)
- [x] Secrets in GNOME keyring — never on disk, never in container static env
- [x] Host `~/.claude.json` cleanup — exa + tavily removed; `research-agent` MCP is the only web tool in the main session
- [ ] LLM scanner layer (`llm-guard` or Haiku) on top of the regex seed
- [ ] External egress proxy container (route outbound through squid/envoy so
      the research-agent itself doesn't hold `NET_ADMIN`)
- [ ] Tier-2 secret isolation (separate systemd user for the MCP server so
      even a compromised main session running as `jonathan` can't read the
      research-agent service account's keyring)

## Directory layout

```
mcp_server/     # host-side MCP server
agent/          # container-side CLAUDE.md + .mcp.json (exa, tavily)
scanner/        # regex + future LLM scanners
scripts/        # run-agent.sh — bwrap invocation per call
reports/        # post-scan output (gitignored)
.devcontainer/  # Ubuntu 24.04 + bubblewrap + Claude Code
```

## Credits

Devcontainer pattern inspired by [trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) — same base image, same bubblewrap approach, adapted for a single-tool MCP research server.
