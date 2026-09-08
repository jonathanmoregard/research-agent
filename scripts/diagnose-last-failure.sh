#!/usr/bin/env bash
# Classifies the most-recent research-agent agent failure into a fixed,
# safe-to-read category.
#
# Reads from the deny-listed audit log; writes ONLY the category enum +
# counters (no raw bytes, no captures from agent output) to a path Claude
# CAN read. Lets Claude triage a normal-call failure without ever loading
# attacker-shaped agent stderr into its context.
#
# Output: ~/.cache/research-agent/last-failure-class.txt
set -euo pipefail

DENY_DIR="/home/jonathan/Repos/research-agent/reports/_quarantine"
FAIL_LOG="$DENY_DIR/agent_failures.jsonl"
OUT="$HOME/.cache/research-agent/last-failure-class.txt"
mkdir -p "$(dirname "$OUT")"

if [[ ! -f "$FAIL_LOG" ]]; then
  printf 'status=no-failure-log\n' > "$OUT"
  cat "$OUT"
  exit 0
fi

LAST=$(tail -n 1 "$FAIL_LOG")
RC=$(jq -r '.exit_code // -1' <<<"$LAST")
TS=$(jq -r '.ts // ""' <<<"$LAST")
ID=$(jq -r '.report_id // ""' <<<"$LAST")
OUTPUT=$(jq -r '.output // ""' <<<"$LAST")
HINT=$(jq -r '.hint // ""' <<<"$LAST")
NBYTES=${#OUTPUT}

# Closed-set classifier — fixed labels, no captures from $OUTPUT.
classify() {
  local t="$1"
  if grep -qE 'REMOTE HOST IDENTIFICATION HAS CHANGED' <<<"$t"; then echo "ssh:host-key-changed"; return; fi
  if grep -qE 'Connection refused'                       <<<"$t"; then echo "ssh:connection-refused"; return; fi
  if grep -qE 'Permission denied \(publickey'            <<<"$t"; then echo "ssh:permission-denied"; return; fi
  if grep -qE 'No route to host'                         <<<"$t"; then echo "ssh:no-route"; return; fi
  if grep -qE 'kex_exchange_identification|timed out'    <<<"$t"; then echo "ssh:timeout"; return; fi
  if grep -qE 'ssh: Could not resolve hostname'          <<<"$t"; then echo "ssh:dns"; return; fi
  if grep -qE 'CLAUDE_CODE_OAUTH_TOKEN'                  <<<"$t"; then echo "agent:claude-auth"; return; fi
  if grep -qE "Can.t find (bind|src) (source|mount)"     <<<"$t"; then echo "bwrap:bind-source-missing"; return; fi
  if grep -qE 'bwrap:'                                   <<<"$t"; then echo "bwrap:other"; return; fi
  if grep -qE 'No such file or directory'                <<<"$t"; then echo "exec:enoent"; return; fi
  if grep -qE 'authentication.*failed|invalid api key|HTTP 40[13]' <<<"$t"; then echo "api:auth-fail"; return; fi
  if grep -qE '429|rate.?limit|TooManyRequests'          <<<"$t"; then echo "api:rate-limit"; return; fi
  if grep -qE 'claude.*not found|command not found'      <<<"$t"; then echo "agent:claude-missing"; return; fi
  if grep -qE 'model.*not available|invalid model'       <<<"$t"; then echo "agent:model-not-available"; return; fi
  if grep -qE 'run.*claude /login|Please run.*login'     <<<"$t"; then echo "agent:claude-needs-login"; return; fi
  if grep -qE 'credit balance|usage limit|spend limit|account.*limit' <<<"$t"; then echo "agent:claude-credit"; return; fi
  if grep -qE 'EXA_API_KEY|TAVILY_API_KEY'               <<<"$t"; then echo "agent:web-key-missing"; return; fi
  if grep -qE 'run-agent:'                               <<<"$t"; then echo "agent:run-agent-script-error"; return; fi
  if grep -qE 'Permission denied'                        <<<"$t"; then echo "fs:permission-denied"; return; fi
  if grep -qE 'mcp|MCP'                                  <<<"$t"; then echo "agent:mcp-fail"; return; fi
  echo "unknown"
}

# Structural fingerprint of the output (no content captures, just shape).
nlines() { echo -n "$1" | grep -c '' || true; }
fingerprint() {
  local t="$1"
  local lines
  lines=$(nlines "$t")
  local first_prefix=""
  if [[ -n "$t" ]]; then
    local first
    # `|| true` survives a future `set -o pipefail`: head -n1 closes
    # stdin early and the upstream printf gets SIGPIPE 141.
    first=$(printf '%s\n' "$t" | { head -n1 || true; })
    # Only ASCII chars + ":" up to first ":" — captures shape like "claude" or "bwrap" or "Error".
    first_prefix=$(printf '%s' "$first" | { sed -E 's/[^a-zA-Z:].*//' | head -c 32 || true; })
  fi
  printf 'lines=%s first_word=%s\n' "$lines" "${first_prefix:-none}"
}

CLASS=$(classify "$OUTPUT")

FP=$(fingerprint "$OUTPUT")

{
  printf 'ts=%s\n'             "$TS"
  printf 'report_id=%s\n'      "$ID"
  printf 'exit_code=%s\n'      "$RC"
  printf 'class=%s\n'          "$CLASS"
  printf 'output_bytes=%s\n'   "$NBYTES"
  printf '%s\n'                "$FP"
  printf 'has_hint=%s\n'       "$([[ -n "$HINT" ]] && echo yes || echo no)"
} > "$OUT"

cat "$OUT"
