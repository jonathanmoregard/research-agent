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

AGENT_DIR="/workspace/agent"
OUT_DIR="${RESEARCH_REPORTS_DIR:-/out}"
SCRATCH_FILE="/scratch/${REPORT_UUID}.md"
FINAL_FILE="${OUT_DIR}/${REPORT_UUID}.md"

# Pre-create the final file so bwrap can bind it writable (bwrap --bind on a
# non-existent target fails). We truncate to zero so the agent writes into a
# known empty file via its /out view. Actually we mount /scratch writable
# and the agent writes there; server.py moves the file after scan.
touch "${FINAL_FILE}"

# Prompt passed via a file to avoid shell-quoting issues with arbitrary content.
PROMPT_CONTENT="$(cat "${PROMPT_FILE}")"

# Build the bwrap invocation. Each run = fresh ephemeral FS.
exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /etc /etc \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind /proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --tmpfs /home/vscode \
  --ro-bind /home/vscode/.local /home/vscode/.local \
  --ro-bind "${AGENT_DIR}" "${AGENT_DIR}" \
  --bind "${FINAL_FILE}" "${SCRATCH_FILE}" \
  --unshare-user \
  --unshare-pid \
  --unshare-uts \
  --unshare-ipc \
  --die-with-parent \
  --new-session \
  --chdir "${AGENT_DIR}" \
  --setenv HOME "/home/vscode" \
  --setenv PATH "/home/vscode/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  --setenv EXA_API_KEY "${EXA_API_KEY:-}" \
  --setenv TAVILY_API_KEY "${TAVILY_API_KEY:-}" \
  --setenv RESEARCH_SCRATCH_PATH "${SCRATCH_FILE}" \
  -- \
  claude -p "${PROMPT_CONTENT}" \
    --allowed-tools "mcp__exa__web_search_exa,mcp__exa__web_fetch_exa,mcp__tavily-remote-mcp__tavily_search,mcp__tavily-remote-mcp__tavily_extract,Write"
