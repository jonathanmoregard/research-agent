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
for domain in "${ALLOWED_DOMAINS[@]}"; do
  mapfile -t ips < <(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u)
  if [[ ${#ips[@]} -eq 0 ]]; then
    log "WARN: no A records for $domain — skipping"
    continue
  fi
  for ip in "${ips[@]}"; do
    ipset add research-allowed "$ip" 2>/dev/null || true
    log "allow $domain -> $ip"
  done
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
