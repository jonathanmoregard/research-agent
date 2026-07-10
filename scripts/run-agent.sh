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
#   - Writable bind of /tool-cache (when present) — persistent PRV +
#     Bolagsverket SQLite indexes; see CACHE_ARGS below.
#   - Network: inherited (exa + tavily MCPs need outbound).
#
# When the jail exits, tmpfs is reaped. Nothing persists except the
# report file and the /tool-cache indexes.

set -euo pipefail

REPORT_UUID="${1:?uuid required}"
PROMPT_FILE="${2:?prompt file required}"
DEPTH="${RESEARCH_DEPTH:-normal}"

# Defense-in-depth: gate the uuid to 32 lowercase hex chars before it
# reaches any path expansion below (touch / bwrap --bind / mktemp).
# The MCP server already validates with `uuid.uuid4().hex`, so a bad
# value can only arrive via direct ssh-into-microvm — but the cost of
# checking here is one regex match.
if ! [[ "${REPORT_UUID}" =~ ^[a-f0-9]{32}$ ]]; then
  echo "run-agent: invalid REPORT_UUID '${REPORT_UUID}'" >&2
  exit 4
fi

# Per-depth tool allowlist. The prompt tells the agent *how* to use these;
# we restrict *which* are callable at all.
EXA_TOOLS="mcp__exa__web_search_exa,mcp__exa__web_fetch_exa"
TAVILY_SEARCH="mcp__tavily-remote-mcp__tavily_search,mcp__tavily-remote-mcp__tavily_extract"
TAVILY_DEEP="mcp__tavily-remote-mcp__tavily_research,mcp__tavily-remote-mcp__tavily_crawl"
# JS-render fallback. Crosses VMs (research-agent -> scraper microvm via
# HTTP on 10.0.2.2:8123) and is an order of magnitude slower than an
# extract API; the agent's CLAUDE.md gates calls to the thin-extract case.
RENDER_TOOLS="mcp__render__render_page"
# Interactive browser sessions (screenshot -> act loop) on the scraper VM.
BROWSE_TOOLS="mcp__render__browse_open,mcp__render__browse_act,mcp__render__browse_screenshot,mcp__render__browse_save_screenshot,mcp__render__browse_close"
# EUIPO trademark word-mark search (REST API, OAuth2). Inert unless
# EUIPO_CLIENT_ID/SECRET are present in the env — the shim errors cleanly
# on call when creds are absent, so listing it here is always safe.
TRADEMARK_TOOLS="mcp__trademark__trademark_search"
# Bolagsverket (Swedish company register) name search via the free CC-BY
# open-data bulk file. Self-contained — no creds. Builds a SQLite index
# on first call (~30-90s cold; <100ms subsequent in same jail).
BOLAGSVERKET_TOOLS="mcp__bolagsverket__bolagsverket_search"
# PRV (Swedish national trademark register) via official open-data FTP.
# Needs opendata.prv.se in the microvm egress allowlist + the persistent
# /tool-cache bind below (888 MiB full-extract index; rebuilding per-jail
# is impractical — see shim header).
PRV_TOOLS="mcp__prv__prv_search"

case "${DEPTH}" in
  normal)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},${RENDER_TOOLS},${BROWSE_TOOLS},${TRADEMARK_TOOLS},${BOLAGSVERKET_TOOLS},${PRV_TOOLS},Write"
    MODEL="claude-opus-4-7"
    ;;
  deep)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},${TAVILY_DEEP},${RENDER_TOOLS},${BROWSE_TOOLS},${TRADEMARK_TOOLS},${BOLAGSVERKET_TOOLS},${PRV_TOOLS},Write"
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
export RESEARCH_RUN_ID="${REPORT_UUID}"
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

# Persistent tool cache. /tool-cache is a RW virtiofs share backed by
# /var/lib/research-agent/tool-cache on the host (nixos-config
# modules/nixos/research-agent-microvm.nix). Binding it into the jail
# lets the PRV (~888 MiB) and Bolagsverket SQLite indexes survive
# across calls; building them into the jail's RAM-backed /tmp dies
# with "database or disk is full". Conditional so the script keeps
# working on guests that predate the share (falls back to the
# ephemeral in-jail path) and on dev hosts without the mount.
CACHE_ARGS=()
if [ -d /tool-cache ]; then
  CACHE_ARGS=(
    --bind /tool-cache /tool-cache
    --setenv PRV_CACHE_DIR "${PRV_CACHE_DIR:-/tool-cache/prv}"
    --setenv BOLAGSVERKET_CACHE_DIR "${BOLAGSVERKET_CACHE_DIR:-/tool-cache/bolagsverket}"
  )
else
  CACHE_ARGS=(--setenv PRV_CACHE_DIR "${PRV_CACHE_DIR:-/tmp/prv-cache}")
fi

bwrap \
  --ro-bind /nix/store /nix/store \
  --ro-bind /run/current-system /run/current-system \
  --ro-bind /run/systemd/resolve /run/systemd/resolve \
  --ro-bind /etc /etc \
  --tmpfs /etc/ssh \
  --ro-bind /bin /bin \
  --ro-bind /usr /usr \
  --proc /proc \
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
  --setenv RESEARCH_RUN_ID "${REPORT_UUID}" \
  --setenv EXA_API_KEY "${EXA_API_KEY}" \
  --setenv TAVILY_API_KEY "${TAVILY_API_KEY}" \
  --setenv EUIPO_CLIENT_ID "${EUIPO_CLIENT_ID:-}" \
  --setenv EUIPO_CLIENT_SECRET "${EUIPO_CLIENT_SECRET:-}" \
  "${CACHE_ARGS[@]}" \
  --setenv CLAUDE_STREAM_IDLE_TIMEOUT_MS "1800000" \
  -- \
  claude -p "${PROMPT_CONTENT}" \
    --add-dir /scratch \
    "${MODEL_FLAGS[@]}" \
    --allowed-tools "${ALLOWED_TOOLS}"
