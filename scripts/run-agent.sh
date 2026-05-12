#!/usr/bin/env bash
# Runs a single research call inside an ephemeral bubblewrap jail.
#
# Usage:
#     run-agent.sh <report_uuid> <prompt_file>
#
# The jail:
#   - Fresh tmpfs at $HOME — no session files, history, or cache leak.
#   - Fresh tmpfs at /scratch — the agent writes its report here.
#   - Read-only bind of /workspace/agent — CLAUDE.md + .mcp.json.
#   - Read-only bind of /usr, /etc, /lib* — system libraries.
#   - Writable bind of /out/<uuid>.md only — final report destination.
#   - Network: inherited (exa + tavily MCPs need outbound).
#
# When the jail exits, tmpfs is reaped. Nothing persists.

set -euo pipefail

REPORT_UUID="${1:?uuid required}"
PROMPT_FILE="${2:?prompt file required}"
DEPTH="${RESEARCH_DEPTH:-normal}"

# Per-depth tool allowlist. The prompt tells the agent *how* to use these;
# we restrict *which* are callable at all.
EXA_TOOLS="mcp__exa__web_search_exa,mcp__exa__web_fetch_exa"
TAVILY_SEARCH="mcp__tavily-remote-mcp__tavily_search,mcp__tavily-remote-mcp__tavily_extract"
TAVILY_DEEP="mcp__tavily-remote-mcp__tavily_research,mcp__tavily-remote-mcp__tavily_crawl"

case "${DEPTH}" in
  normal)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},Write"
    MODEL="claude-opus-4-7"
    ;;
  deep)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},${TAVILY_DEEP},Write"
    MODEL="claude-opus-4-7"
    ;;
  *)
    # fast is handled server-side (direct Exa call, no agent);
    # anything else here is an error.
    echo "run-agent: invalid RESEARCH_DEPTH=${DEPTH}" >&2
    exit 2
    ;;
esac

# Optional per-depth model override via env.
case "${DEPTH}" in
  normal) MODEL="${RESEARCH_MODEL_NORMAL:-$MODEL}" ;;
  deep)   MODEL="${RESEARCH_MODEL_DEEP:-$MODEL}" ;;
esac

MODEL_FLAGS=()
if [[ -n "${MODEL}" ]]; then
  MODEL_FLAGS=(--model "${MODEL}")
fi

AGENT_DIR="/workspace/agent"
OUT_DIR="${RESEARCH_REPORTS_DIR:-/out}"
SCRATCH_FILE="/scratch/${REPORT_UUID}.md"
FINAL_FILE="${OUT_DIR}/${REPORT_UUID}.md"

# Pre-create the final file so bwrap can bind it writable. bwrap's
# --unshare-user maps the outer uid to 'nobody' (65534) inside the jail;
# the bound file must be writable by that uid, so we chmod 666 up front.
# The file is ephemeral — only valid for this one call.
touch "${FINAL_FILE}"
chmod 666 "${FINAL_FILE}"

# Prompt passed via a file to avoid shell-quoting issues with arbitrary content.
PROMPT_CONTENT="$(cat "${PROMPT_FILE}")"

# Claude Code does NOT expand ${VAR} in `.mcp.json` `url` / `headers` fields.
# Render a resolved copy with env substitution and bind-mount it over the
# read-only original inside the jail. Ephemeral per call; cleaned up on exit.
RENDERED_MCP=$(mktemp --suffix=.mcp.json)
# Invariant: the rendered file holds substituted EXA_API_KEY +
# TAVILY_API_KEY values. It MUST live on /tmp (in-VM disk), never on
# /out (virtiofs share, visible to the host). Without this guard, a
# future operator who exports TMPDIR=/out would silently leak keys to
# the host's reports/ dir.
case "${RENDERED_MCP}" in
  /tmp/*) ;;
  *) echo "run-agent: refusing to render .mcp.json outside /tmp (got ${RENDERED_MCP})" >&2; exit 3 ;;
esac
chmod 600 "${RENDERED_MCP}"
python3 -c 'import os,sys; sys.stdout.write(os.path.expandvars(sys.stdin.read()))' \
  < "${AGENT_DIR}/.mcp.json" > "${RENDERED_MCP}"
trap 'rm -f "${RENDERED_MCP}"' EXIT

# Build the bwrap invocation. Each run = fresh ephemeral FS.
#
# NixOS guest layout (post-microvm migration):
#   - /nix/store         — all binaries + libraries live here
#   - /run/current-system/sw/bin — system PATH (symlinks into /nix/store)
#   - /etc                — system config (incl. resolv.conf, nsswitch)
#   - /bin/sh             — symlink to bash in /nix/store
#   - /usr/bin/env        — symlink to coreutils
# No /lib, /lib64, /sbin at the root. Binding those (as the docker era
# did) fails with "Can't find source path /lib".
HOME_DIR="/home/agent"
# Strip env vars that nested `claude -p` inherits and that trigger a
# known ~50%-rate hang when the child runs under CLAUDECODE=1 +
# CLAUDE_CODE_ENTRYPOINT=cli (anthropic/claude-code#26190). The MCP
# server spawning us already runs under those vars on the host; though
# they shouldn't propagate through ssh-into-microvm, belt-and-braces
# unset is cheap.
unset CLAUDECODE CLAUDE_CODE_ENTRYPOINT

bwrap \
  --ro-bind /nix/store /nix/store \
  --ro-bind /run/current-system /run/current-system \
  --ro-bind /run/systemd/resolve /run/systemd/resolve \
  --ro-bind /etc /etc \
  --ro-bind /bin /bin \
  --ro-bind /usr /usr \
  --ro-bind /proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --tmpfs "${HOME_DIR}" \
  --ro-bind "${AGENT_DIR}" "${AGENT_DIR}" \
  --ro-bind "${RENDERED_MCP}" "${AGENT_DIR}/.mcp.json" \
  --bind "${FINAL_FILE}" "${SCRATCH_FILE}" \
  --unshare-user \
  --unshare-pid \
  --unshare-uts \
  --unshare-ipc \
  --die-with-parent \
  --new-session \
  --as-pid-1 \
  --chdir "${AGENT_DIR}" \
  --setenv HOME "${HOME_DIR}" \
  --setenv PATH "/run/current-system/sw/bin:/run/current-system/sw/sbin" \
  --setenv RESEARCH_SCRATCH_PATH "${SCRATCH_FILE}" \
  --setenv EXA_API_KEY "${EXA_API_KEY}" \
  --setenv TAVILY_API_KEY "${TAVILY_API_KEY}" \
  --setenv CLAUDE_STREAM_IDLE_TIMEOUT_MS "1800000" \
  -- \
  claude -p "${PROMPT_CONTENT}" \
    --add-dir /scratch \
    "${MODEL_FLAGS[@]}" \
    --allowed-tools "${ALLOWED_TOOLS}"
