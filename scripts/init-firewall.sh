#!/usr/bin/env bash
# Container-startup firewall. Blocks all outbound traffic except the domains
# strictly required by the research-agent: Anthropic API (Claude), Exa, Tavily.
#
# Pattern borrowed from trailofbits/claude-code-devcontainer's init-firewall.
# Each domain is resolved at startup and its IPs pinned into an ipset; the
# OUTPUT chain drops everything that does not hit the set or localhost.
#
# Requires the container to run with --cap-add=NET_ADMIN (not SYS_ADMIN;
# NET_ADMIN only covers network configuration).

set -euo pipefail

ALLOWED_DOMAINS=(
  "api.anthropic.com"
  "api.exa.ai"
  "mcp.exa.ai"
  "api.tavily.com"
  "mcp.tavily.com"
)

log() { echo "[init-firewall] $*"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "ERROR: $1 not installed"; exit 1
  fi
}

require_cmd iptables
require_cmd ipset
require_cmd getent

# Flush existing rules so re-runs are idempotent.
iptables -F OUTPUT
iptables -F INPUT
ipset destroy research-allowed 2>/dev/null || true
ipset create research-allowed hash:ip family inet

# Resolve each allowed domain to its current A records and pin them.
#
# DNS at container boot can race the resolver coming up — getent has returned
# an empty result for api.anthropic.com under load even though the host
# resolver returns IPs a second later. Previously this silently `continue`d,
# the firewall came up without Anthropic in the allowlist, and any agent
# call to Claude hung until AGENT_TIMEOUT (10 min). Now: retry with backoff,
# and if a domain ultimately fails to resolve, abort startup. Container
# entrypoint will exit non-zero and systemd's Restart=on-failure will retry
# from scratch with a (hopefully) warm resolver.
DNS_RETRIES="${DNS_RETRIES:-5}"
DNS_RETRY_SLEEP="${DNS_RETRY_SLEEP:-2}"

resolve_or_die() {
  local domain="$1" attempt ips_str
  for ((attempt=1; attempt<=DNS_RETRIES; attempt++)); do
    ips_str=$(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u)
    if [[ -n "$ips_str" ]]; then
      printf '%s\n' "$ips_str"
      return 0
    fi
    if (( attempt < DNS_RETRIES )); then
      log "DNS miss for $domain (attempt $attempt/$DNS_RETRIES), retrying in ${DNS_RETRY_SLEEP}s..."
      sleep "$DNS_RETRY_SLEEP"
    fi
  done
  log "ERROR: failed to resolve $domain after $DNS_RETRIES attempts — aborting startup"
  return 1
}

for domain in "${ALLOWED_DOMAINS[@]}"; do
  # Capture into a string first so `|| exit 1` propagates the resolver's
  # exit code — `mapfile < <(cmd)` swallows it (process substitution's
  # exit code is not surfaced to the caller).
  ips_text=$(resolve_or_die "$domain") || exit 1
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    ipset add research-allowed "$ip" 2>/dev/null || true
    log "allow $domain -> $ip"
  done <<< "$ips_text"
done

# Always allow loopback and DNS (needed for MCP clients to resolve hosts).
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -i lo -j ACCEPT

# DNS via container runtime resolver (most Docker setups route DNS to
# 127.0.0.11, which is already covered by the loopback rule; explicit UDP
# allow kept for robustness).
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow established / related traffic so responses flow back.
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow outbound HTTPS only to pinned IPs.
iptables -A OUTPUT -p tcp --dport 443 -m set --match-set research-allowed dst -j ACCEPT

# Default deny for everything else going out.
iptables -A OUTPUT -j DROP
iptables -A INPUT  -j DROP

log "firewall active — allowlist: ${ALLOWED_DOMAINS[*]}"
