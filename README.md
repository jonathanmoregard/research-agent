# research-agent

Isolated web-research subsystem for Claude Code. Main session delegates via a single MCP tool; all web access happens inside a dev container. Reports are scanned before delivery.

## Interface

MCP tool exposed to the host Claude session:

```
research(prompt: str) -> { status: "done" | "error", report_path: str, error?: str }
```

One call, one report. Main session waits for the tool to return, then tells the user where to find the file.

## Architecture

```
host Claude session
        |
        | MCP call: research(prompt)
        v
mcp_server/server.py              (process on host)
        |
        | spawn / IPC
        v
agent (Claude Code inside dev container)
        |
        | uses exa + tavily MCPs (container-only)
        | writes report to /scratch/<uuid>.md
        v
scanner/regex.py                  (runs on container output)
        |
        | pass  -> mv to /reports/<uuid>.md, return path
        | fail  -> delete scratch, return error
        v
host Claude session receives result
```

### Trust boundaries
- **Host Claude**: no exa/tavily keys, no web MCPs, cannot see scratch dir.
- **Container Claude**: exa/tavily configured, writes only to `/scratch`.
- **Scanner**: regex-seed now; LLM layer planned.
- **Reports dir**: host-readable *only after scan passes*.

## Status
- [x] Repo skeleton
- [x] MCP server stub (subprocess spawn of container agent)
- [x] Regex scanner seed
- [ ] Dev container based on Trail of Bits image
- [ ] Long-running container worker (IPC instead of spawn-per-call)
- [ ] LLM scanner layer (`llm-guard` or Haiku-based)
- [ ] Network egress allowlist (exa.ai, tavily.com only)
- [ ] Host-side hook: remove exa/tavily from main `~/.claude.json`

## Roadmap
See [docs/roadmap.md](docs/roadmap.md) (planned).

## Directory layout
```
mcp_server/    # host-side MCP server
agent/         # container-side Claude config + skills
scanner/       # regex + future LLM scanners
reports/       # post-scan output (gitignored)
.devcontainer/ # container build + runtime config
```
