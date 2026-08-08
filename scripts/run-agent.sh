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
#   - Memory: bounded by a per-call cgroup cap; see MEMGUARD below and
#     lib/memguard.sh.
#
# When the jail exits, tmpfs is reaped. Nothing persists except the
# report file and the /tool-cache indexes.

set -euo pipefail

# Resolved before anything else so the memguard helper can be sourced
# regardless of the caller's cwd (the MCP server invokes us by absolute
# path from the ssh login shell's $HOME).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# `source=` lets `shellcheck -x` follow the helper; `disable=SC1091` keeps
# a plain `shellcheck scripts/run-agent.sh` (no -x) clean too, since the
# path is only resolvable at runtime.
# shellcheck source=lib/memguard.sh disable=SC1091
. "${SCRIPT_DIR}/lib/memguard.sh"

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
# tavily_shim.py implements tavily_search + tavily_extract and nothing else,
# so there is no deep-only Tavily tier to allowlist.
TAVILY_SEARCH="mcp__tavily-remote-mcp__tavily_search,mcp__tavily-remote-mcp__tavily_extract"
# JS-render fallback. Crosses VMs (research-agent -> scraper microvm via
# HTTP on 10.0.2.2:8123) and is an order of magnitude slower than an
# extract API; the agent's CLAUDE.md gates calls to the thin-extract case.
RENDER_TOOLS="mcp__render__render_page,mcp__render__intercept_page"
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

# Default model for BOTH agent depths (fast runs no agent at all — it is
# a direct server-side Exa call, so no model applies there). Single
# constant rather than a literal repeated per depth so the two pins can
# never silently drift apart.
#
# Opus 5 as of 2026-08-08 (was claude-fable-5). Bare `claude-opus-5`, no
# `[1m]` suffix: the id is charset-gated by MODEL_ID_RE in server.py and
# again below, and neither pattern admits brackets. The CLI recognises the
# bare id (`claude --model claude-opus-5` exits 0; an unrecognised id exits
# 1 with "is not a model this version of Claude Code recognizes"), so it
# already applies the model's real context window without the suffix.
#
# Overridable per depth via RESEARCH_MODEL_NORMAL / RESEARCH_MODEL_DEEP,
# and per call via RESEARCH_MODEL (the MCP tool's `model` param) — see
# below; this constant is only the floor when nothing else is set.
DEFAULT_MODEL="claude-opus-5"

case "${DEPTH}" in
  normal)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},${RENDER_TOOLS},${BROWSE_TOOLS},${TRADEMARK_TOOLS},${BOLAGSVERKET_TOOLS},${PRV_TOOLS},Write"
    MODEL="${DEFAULT_MODEL}"
    ;;
  deep)
    ALLOWED_TOOLS="${EXA_TOOLS},${TAVILY_SEARCH},${RENDER_TOOLS},${BROWSE_TOOLS},${TRADEMARK_TOOLS},${BOLAGSVERKET_TOOLS},${PRV_TOOLS},Write"
    MODEL="${DEFAULT_MODEL}"
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

# Per-call model override (RESEARCH_MODEL, set by the MCP server's `model`
# tool param) beats both the default and the per-depth env pins.
if [[ -n "${RESEARCH_MODEL:-}" ]]; then
  MODEL="${RESEARCH_MODEL}"
fi

# Gate the FINAL model id whatever its source (default, per-depth env,
# per-call ssh env) before it reaches claude's argv. First char must be
# alphanumeric so a value can never be parsed as a flag (e.g.
# '--dangerously-...' would otherwise ride in as the --model value one
# argv-parser quirk away from flag injection).
if [[ -n "${MODEL}" ]] && ! [[ "${MODEL}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "run-agent: invalid model id '${MODEL}'" >&2
  exit 5
fi

MODEL_FLAGS=()
if [[ -n "${MODEL}" ]]; then
  MODEL_FLAGS=(--model "${MODEL}")
fi

# Per-call memory cap. Validated here, alongside the other config gates,
# so a typo'd RESEARCH_MEM_MAX fails immediately and loudly instead of
# surfacing 20 minutes later as an opaque systemd-run error. The argv is
# assembled further down, just above bwrap. See lib/memguard.sh.
if ! MEM_CAP="$(memguard_cap)"; then
  echo "run-agent: invalid RESEARCH_MEM_MAX '${RESEARCH_MEM_MAX:-}' (want bytes or K/M/G/T suffix, e.g. 2G; or off)" >&2
  exit 6
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
# RESEARCH_RUN_ID follows the same dual path as EXA_API_KEY: baked into the
# rendered .mcp.json (so shims that read it at startup see it) AND passed via
# --setenv below (so the running agent process and its children see it too).
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

# MEMGUARD — per-call memory cap.
#
# bwrap isolates the filesystem but shares the guest's memory with every
# other in-flight call. Without a cap, one runaway call drives the whole
# 6 GiB VM into reclaim, stalls sshd, and gets the VM restarted by the
# host watchdog — killing unrelated concurrent calls. Wrapping bwrap in
# its own transient cgroup scope makes a runaway call die alone.
#
# MEMGUARD_ARGV is EMPTY when the cap is disabled or unavailable, in which
# case bwrap runs exactly as it did before this block existed. Expanding
# an empty array under `set -u` is safe on bash >= 4.4 (guest ships 5.3).
MEMGUARD_ARGV=()
if [[ "${MEM_CAP}" != "off" ]]; then
  if memguard_available; then
    # Scope name is derived from the (already regex-gated) report uuid, so
    # concurrent calls can never collide on a unit name and `systemctl
    # --user status research-<uuid>.scope` is a usable live debug handle.
    mapfile -t MEMGUARD_ARGV < <(
      memguard_scope_argv \
        "${MEM_CAP}" \
        "research-${REPORT_UUID}.scope" \
        "${SCRIPT_DIR}/lib/memguard.sh"
    )
    echo "run-agent: memory cap ${MEM_CAP} armed (scope research-${REPORT_UUID}.scope)" >&2
  else
    # Degrade rather than fail: the guest always has a user manager (we
    # run inside an ssh session), but a developer checkout or a bare
    # container does not, and refusing to run there would make the script
    # untestable outside the VM. Loud, greppable, and never silent.
    echo "run-agent: WARNING memory cap ${MEM_CAP} requested but systemd-run --user --scope is unavailable — running UNCAPPED" >&2
  fi
fi

"${MEMGUARD_ARGV[@]}" \
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
